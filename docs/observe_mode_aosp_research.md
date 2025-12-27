# Android Observe Mode（Passive Observe）とNFC-Fポーリングフレーム通知のAOSP調査メモ

本ドキュメントは、AOSPのNFCスタック（`platform/system/nfc` と `platform/packages/apps/Nfc`）を根拠に、**Observe Mode（受信観測のみ）**で **NFC-F（FeliCa/T3T）のポーリング（SENSF_REQ）をHostへ通知できる理由**と、**同じ状態でHostから任意送信（Raw TX）が成立しにくい理由**を整理したものです。  
**攻撃成立に直結する“注入/バイパス実装”は扱いません**（PoCやフック手順は含めません）。

---

## 0. 参照ソース（このワークスペースで収集済み）

本調査で重要だったファイルは `ref_aosp/` に精選コピーしています。

- `ref_aosp/system_nfc/`
  - `nci_defs.h`
  - `nfa_dm_api.cc`
  - `nfa_dm_act.cc`
  - `nfa_dm_int.h`
  - `nci_hmsgs.cc`
- `ref_aosp/packages_apps_Nfc/`
  - `NativeNfcManager.cpp`
  - `NfcService.java`
  - `DeviceHost.java`
  - `HostEmulationManager.java`
  - `NfcProprietaryCaps.java`
  - `NfcShellCommand.java`

---

## 1. Observe Modeの“実体”は標準NCIではなくAndroid拡張（Vendor Specific）

`system/nfc` の `nci_defs.h` に、Android独自の拡張コマンド／通知が定義されています。

- **Android Proprietary group**
  - `GID = 0x0F (NCI_GID_PROP)`
  - `OID = 0x0C (NCI_MSG_PROP_ANDROID)`
- **Observe Mode制御**
  - `NCI_ANDROID_PASSIVE_OBSERVE (sub-opcode = 0x2)`
  - `NCI_QUERY_ANDROID_PASSIVE_OBSERVE (sub-opcode = 0x4)`
- **ポーリングフレーム通知**
  - `NCI_ANDROID_POLLING_FRAME_NTF (sub-opcode = 0x3)`

つまり、あなたが「Observe Mode」と呼んでいる挙動は、少なくともAOSPの参照実装では **“Android拡張（NFCC/ファームが実装するベンダ機能）”**として扱われます。  
このため、**どこまでのRF動作（Listen応答を含むか/含まないか）はNFCCファーム実装依存**になりやすい、というのが大前提です。

### 1.1 サポート有無はGET_CAPS（Android拡張）で判定される

`packages/apps/Nfc` 側には、NFCCが返すAndroid拡張capabilityをパースする `NfcProprietaryCaps` があり、少なくとも以下を識別します。

- **Passive Observe Modeのサポート形態**
  - `NOT_SUPPORTED`
  - `SUPPORT_WITH_RF_DEACTIVATION`
  - `SUPPORT_WITHOUT_RF_DEACTIVATION`
- **Polling Frame Notification（ポーリングフレーム通知）のサポート**
- （他）Power saving / Autotransact polling loop filter 等

JNI（`NativeNfcManager.cpp`）では `NCI_ANDROID_GET_CAPS` を送信し、応答を `gCaps` に格納するコードがあり、上位でこの配列を解釈して機能可否を決める設計になっています。

---

## 2. RX（ポーリング観測）がHostに上がる経路：VSC callback → Java通知

### 2.1 Observe ModeのON/OFFは `NFA_SendVsCommand()` で行う

`packages/apps/Nfc` のJNI層（`NativeNfcManager.cpp`）では、Observe ModeのON/OFFを **Vendor Specific CommandとしてNFAへ投げる**実装になっています。

- `nfcManager_setObserveMode(enable)` が `NCI_ANDROID_PASSIVE_OBSERVE` を送る
- `nfcManager_isObserveModeEnabled()` が `NCI_QUERY_ANDROID_PASSIVE_OBSERVE` を送る
- 応答は `nfaVSCallback()` で受け、`gObserveModeEnabled` を更新

さらに、環境によっては Observe Mode切替の前に `startRfDiscovery(false)`（RF discovery停止）を挟む実装になっており、**Observe Mode切替が“RF discovery/状態機械”と強く結び付けて設計されている**ことが読み取れます。

### 2.2 ポーリングフレーム通知は“リンクアクティベーション不要”で上がる

同じ `nfaVSCallback()` 内に `NCI_ANDROID_POLLING_FRAME_NTF` の分岐があり、受け取ったpayloadをそのままJavaへ転送しています（`notifyPollingLoopFrame(len, bytes)`）。

重要なのは、この通知が **“NFAの通常のRFリンク（Activated状態）”経路ではなく、Vendor Specific Notification経路**で扱われている点です。  
これにより、Observe Mode下で **NFC-FのSENSF_REQ（Polling）をHost側が観測できる**こと自体は、AOSPの設計として自然に説明できます。

---

## 3. TX（Raw送信）が成立しにくい根拠：NFA_SendRawFrameの前提が「リンクActivated」

### 3.1 APIコメントと入力検証が“Activated前提”

`system/nfc` の `nfa_dm_api.cc` にある `NFA_SendRawFrame()` のコメントは明確です：

- “**This function can only be called after NFC link is activated.**”

さらに実装でも、入力検証が **NFAのDiscovery状態（`disc_state`）と`activated_protocol`**に依存しており、「今は送信可能なRFリンクがある」という前提を強く要求します。

### 3.2 DM state machine側でも“送信はPOLL_ACTIVE/LISTEN_ACTIVEのみ”

`system/nfc` の `nfa_dm_act.cc` にある `nfa_dm_act_send_raw_frame()` では、送信処理に入る条件が以下に限定されています：

- `disc_state == NFA_DM_RFST_POLL_ACTIVE` または `NFA_DM_RFST_LISTEN_ACTIVE`

Observe Modeでポーリングフレーム通知を受けている状況は、多くの場合 **“Discovery中（`NFA_DM_RFST_DISCOVERY`）で、Activatedに入っていない”**ため、ここで **送信処理に到達できない**（`NFC_STATUS_FAILED`で終わる）可能性が高い、というのがAOSPコードからの最も堅い説明です。

> まとめると：  
> **RX通知（VSC NTF）は「Activated不要」**だが、  
> **TX（NFA_SendRawFrame）は「Activated必須」**で設計されている。

---

## 4. Apps側（NfcService / HCE）から見たObserve Modeの位置づけ

### 4.1 Observe Modeは“トランザクション中は切替禁止”

`NfcService.java` の `setObserveMode()` は、**HCEトランザクション中はObserve Modeを変更できない**というガードを持っています。

- `mCardEmulationManager.isHostCardEmulationActivated()` なら拒否

これは、Observe Modeが「単なるログ機能」ではなく、**トランザクション（HCE/OffHost含む）と排他的に扱う設計**であることを示唆します。

### 4.2 HostEmulationManagerは“ポーリング検知→（必要なら）Observe Modeを一時解除”

`HostEmulationManager.java` では `onPollingLoopDetected()` を起点にフレームをサービスへ配送しつつ、条件により「1トランザクションだけ許可する」ような制御（Observe Modeの無効化）も行っています。

このロジックは、Observe Modeが **“eSE/HCEの応答を抑止して観測する”**という目的で導入され、必要に応じて **通常のトランザクションに戻す**ことを前提にしていることの裏付けになります。

---

## 5. あなたの仮説に対するAOSPベースの整理（攻撃手順は除外）

### 5.1 「RXパスがあるならTXも物理的には可能では？」について

AOSP側の設計としては、**RX（観測）とTX（データ交換）を同じ“リンク状態”の上に置いていません**。

- 観測：`NCI_ANDROID_POLLING_FRAME_NTF`（VSC NTF）として上がる  
- 送信：`NFA_SendRawFrame()` → DM state machineが **Activated状態**を要求

したがって、AOSP観点では「物理的に可能か否か」より先に、**“その状態では送信APIが成立する前提が揃っていない”**という整理になります。

### 5.2 どこが“真の要因”か（Software vs Firmware）

このコードから言える最小限の結論は：

- **Software（AOSP）側**：`NFA_SendRawFrame()` がActivatedを要求し、DM state machineでも状態を絞っている  
- **Firmware/NFCC側**：Observe Modeの実体がAndroid拡張で、通知（Polling Frame NTF）を出す一方で“応答送信”まで許すかは実装依存

よって、一般論としては **二重に制約される**と見るのが安全です（AOSPだけ外しても、NFCCが許さない可能性が残る）。

---

## 6. 次に深掘りするなら（防御/検証として安全な範囲）

PoC（注入）を作らずに、追加で確度を上げる調査ポイントは以下です。

- **(A) Observe Mode時のNFA Discovery stateの観測**  
  `libnfc_nci`のログで、Observe ON時に `disc_state` がどう遷移しているか（Discoveryのままか、Listen Active相当へ入るのか）
- **(B) NFCCが“送信可能なRF interface”を作らない設計かの確認**  
  ベンダのNCI拡張仕様（もし入手可能なら）で、Passive Observeが「送信禁止」かどうかを確認
- **(C) NFC-F（T3T）に関するAOSPのListen設定（LF_T3T_*）の整理**  
  `nfa_dm_act.cc` が初期値として `LF_T3T_IDENTIFIERS_*`/`LF_T3T_PMM` 相当をセットしている点があるため、Listen Fの構成とObserveの関係を切り分ける

---

## 7. 追加調査：NFC-F（HCE-F/OffHost）ルーティングとSystemCode routingの実装（AOSP）

このセクションは、あなたの背景課題「`SC=0xFFFF`のポーリングでeSEが固定IDmを返す」現象を、**AOSPのルーティング設計**の観点で“起こりやすい条件”として整理するための材料です（`SC=0xFFFF`そのものの注入/回避手順は扱いません）。

### 7.1 Apps側：HCE-Fの“SystemCode/T3T識別子”はコントローラへ登録して運用する

`SystemCodeRoutingManager` は、HCE-Fのために `T3tIdentifier(systemCode, nfcid2, t3tPmm)` の増減を管理し、増減分を `NfcService.registerT3tIdentifier()/deregisterT3tIdentifier()` に委譲します。

- `SystemCodeRoutingManager.configureRouting()`  
  - 追加：`NfcService.getInstance().registerT3tIdentifier(systemCode, nfcid2, t3tPmm)`
  - 削除：`NfcService.getInstance().deregisterT3tIdentifier(systemCode, nfcid2, t3tPmm)`
  - 最後に `commitRouting()`

この時点で、AOSPのHCE-Fは「Hostが任意応答を作る」より先に、**NFCCのルーティング表・Listen-F識別子登録**に依存していることが分かります。

### 7.2 JNI側：`registerT3tIdentifier()` は“DH上のFeliCa SystemCode登録”＋“SystemCode routing登録”を行う

`RoutingManager::registerT3tIdentifier()`（JNI/C++）は、受け取ったT3T Identifier（SystemCode + NFCID2 + PMm）を分解して、次の2つを行います。

- `NFA_CeRegisterFelicaSystemCodeOnDH(systemCode, nfcid2, t3tPmm, ...)`  
  → **DH（ホスト）側のListen-F（FeliCa）識別子登録**
- `NFA_EeAddSystemCodeRouting(systemCode, NCI_DH_ID, SYS_CODE_PWR_STATE_HOST)`（SCBRサポート時）  
  → **SystemCode routingをDHへ向けて追加**

これが意味するのは、AOSPの想定するHCE-Fは「Observeで受信だけ見てホストが勝手にSENSF_RESを返す」ではなく、**“事前にSystemCode/NFCID2/PMmを登録し、RFルーティングでDHへ選択される状態を作った上で”動く**設計だという点です。

### 7.3 デフォルトのNFC-Fルート（`NAME_DEFAULT_NFCF_ROUTE`）がeSE側にあると、ポーリングがeSEへ吸われやすい

`RoutingManager` は `NAME_DEFAULT_NFCF_ROUTE`（`mDefaultFelicaRoute`）を設定として読み込み、EE情報（SEの対応Tech）と合わせて **NFC-FのTech/Protoルーティング**を組み立てます。

このため、端末設定（`libnfc-nci.conf` や OEM overlay）で **NFC-FのデフォルトルートがeSE** になっていると、

- Observe Modeを使わない通常系では、ポーリング（特にwildcard側）が **eSEへ到達して応答**しやすい
- Host側がHCE-Fとして介入するには、上記の **SystemCode routing / T3T識別子登録**でDHへ寄せる必要がある

…という構図が、AOSPのルーティング実装と整合します。

#### 7.3.1 AOSP実装の要点：SEがNFC-F対応なら“DHのFルートは消される”

`RoutingManager::updateEeTechRouteSetting()` は、`NAME_DEFAULT_NFCF_ROUTE`で指定されたEEが **実際に`lf_protocol`を持つ（NFC-F対応）**場合、そのEEに対して `NFA_EeSetDefaultTechRouting(..., NFA_TECHNOLOGY_MASK_F, ...)` を構成します。  
その結果、`allSeTechMask`に `NFA_TECHNOLOGY_MASK_F` が立つと、最後に **DH側のNFC-F Techルートを明示的にクリア**します。

この動きは「端末がeSEでNFC-Fを扱える」構成だと、AOSPが **HostへFをルートしない（あるいは最小化する）**方向に倒れる、という意味になります。`SC=0xFFFF`のwildcardポーリングが“ホストで制御できない”状況を作りやすい条件として重要です。

### 7.4 SystemCode routing（SCBR）はAOSP的に“サポート有無”があり、挙動が端末依存になり得る

`RoutingManager::updateDefaultRoute()` では `NFA_EeAddSystemCodeRouting(mDefaultSysCode, mDefaultSysCodeRoute, ...)` を呼び、戻りが `NFA_STATUS_NOT_SUPPORTED` の場合は「SCBR not supported」として扱います。

つまり、SystemCode routingは **NCI2.0かつNFCC側サポート前提**で、端末により **ルーティングの効き方（DHへ寄せられるか）が変わりうる**ことが、AOSPコード上からも示唆されます。


