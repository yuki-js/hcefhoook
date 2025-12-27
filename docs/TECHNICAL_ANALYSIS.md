# Android NFC Observe Mode SENSF_RES Injection: Technical Analysis

## 概要 (Overview)

本ドキュメントは、Android 15以降のObserve Modeを活用し、Host側からSENSF_RESを強制送信する技術的可能性についての詳細な調査結果をまとめたものです。

## 目次

1. [技術背景](#1-技術背景)
2. [ブロック要因の特定](#2-ブロック要因の特定-blocking-factors)
3. [NCIレベルの回避策](#3-nciレベルの回避策-nci-level-workarounds)
4. [具体的な実装アプローチ](#4-具体的な実装アプローチ-implementation-approach)
5. [フック対象関数一覧](#5-フック対象関数一覧)
6. [Fridaスクリプト例](#6-fridaスクリプト例)
7. [制限事項と考慮点](#7-制限事項と考慮点)

---

## 1. 技術背景

### 1.1 Observe Modeとは

Observe Modeは、Android 15で導入されたNFCコントローラの動作モードです：

- **目的**: NFCCがRFフィールドを受信しても自動応答を行わない
- **eSEの沈黙**: Secure Elementも応答を抑制
- **Hostへの通知**: 受信したポーリングフレームを`NCI_ANDROID_POLLING_FRAME_NTF`経由でHostに通知

### 1.2 SENSF_REQ/RES構造

```
SENSF_REQ (リーダーから):
[Length(1B)] [Cmd:00] [SystemCode:2B] [RC(1B)] [TSN(1B)]
例: 06 00 FF FF 00 03

SENSF_RES (タグ/エミュレータから):
[Length(1B)] [Cmd:01] [IDm(8B)] [PMm(8B)] [RD(0-2B opt)]
例: 11 01 02FE010203040506 00F0FFD2FE1F1F00
     ^-- Length = 17 (0x11) = 1(cmd) + 8(IDm) + 8(PMm) = 17バイト
```

### 1.3 問題の核心

SC=0xFFFF（ワイルドカード）のポーリングに対し、通常のHCE-FではeSEが勝手に固定IDmを返信し、Host側での制御が不可能。Observe ModeでeSEを沈黙させることには成功したが、Hostからの応答送信がブロックされている。

---

## 2. ブロック要因の特定 (Blocking Factors)

### Q1への回答: 通信を阻害する「真の要因」はどこにあるか？

調査の結果、**複数階層でのブロッキング**が確認されました：

### 2.1 レイヤー1: NFA (NFC Forum Adaptation) レイヤー - 主要ブロック

**ファイル**: `nfa_dm_act.cc` (実際のAOSPソース)
**関数**: `nfa_dm_act_send_raw_frame()`

```cpp
// From AOSP nfa_dm_act.cc lines 1168-1197
bool nfa_dm_act_send_raw_frame(tNFA_DM_MSG* p_data) {
  tNFC_STATUS status = NFC_STATUS_FAILED;

  /* If NFC link is activated */
  if ((nfa_dm_cb.disc_cb.disc_state == NFA_DM_RFST_POLL_ACTIVE) ||
      (nfa_dm_cb.disc_cb.disc_state == NFA_DM_RFST_LISTEN_ACTIVE)) {
    nfa_dm_cb.flags |= NFA_DM_FLAGS_RAW_FRAME;
    // ... data transmission proceeds ...
    status = NFC_SendData(NFC_RF_CONN_ID, (NFC_HDR*)p_data);
  }

  if (status == NFC_STATUS_FAILED) {
    // BLOCKED: State check failed, data not sent
    return true;  // Free buffer, operation failed
  }
  return false;
}
```

**問題点**: 
- Observe Modeでは状態が`NFA_DM_RFST_DISCOVERY (0x01)`のまま
- `POLL_ACTIVE (0x04)` または `LISTEN_ACTIVE (0x05)`でないと送信処理に入らない
- **これが主要なブロッキングポイント**

### 2.2 レイヤー2: NFA_SendRawFrame() API

**ファイル**: `nfa_dm_api.cc`
**関数**: `NFA_SendRawFrame()` (lines 931-965)

```cpp
tNFA_STATUS NFA_SendRawFrame(uint8_t* p_raw_data, uint16_t data_len,
                             uint16_t presence_check_start_delay) {
  // Parameter validation only - no state check here
  if ((data_len == 0) || (p_raw_data == nullptr))
    return (NFA_STATUS_INVALID_PARAM);
    
  // Create message and send to NFA message queue
  p_msg->event = NFA_DM_API_RAW_FRAME_EVT;
  nfa_sys_sendmsg(p_msg);
  return (NFA_STATUS_OK);  // Always succeeds if params valid
}
```

**特徴**:
- API自体は状態チェックなし
- メッセージをキューに送信するだけ
- 実際のブロックは `nfa_dm_act_send_raw_frame()` で発生

### 2.3 レイヤー3: NCI (NFC Controller Interface) レイヤー

**ファイル**: `nci_hmsgs.cc`
**関数**: `nci_snd_data()`

```cpp
tNCI_STATUS nci_snd_data(uint8_t conn_id, BT_HDR* p_buf) {
    // STATE VALIDATION (BLOCKING POINT #1)
    if (nfc_cb.nfc_state != NFC_STATE_OPEN) {
        return NCI_STATUS_FAILED;
    }
    
    // CONNECTION VALIDATION (BLOCKING POINT #2)
    if (conn_id >= NCI_MAX_CONN_CBS || !nfc_cb.conn_cb[conn_id].p_cback) {
        return NCI_STATUS_FAILED;
    }
    // ...
}
```

**問題点**:
- `nfc_state`は通常`NFC_STATE_OPEN`だが、接続IDの検証で失敗する可能性
- Observe Modeでは有効な接続が確立されていない

### 2.4 レイヤー4: HAL (Hardware Abstraction Layer)

**ファイル**: `nfc_hal_api.h`
**関数**: `hal_nfc_write()`

```cpp
int hal_nfc_write(uint16_t data_len, uint8_t* p_data) {
    // HAL層では最小限のチェックのみ
    return transport_write(nfc_dev_node, p_data, data_len);
}
```

**特徴**:
- HAL層自体は状態チェックをほとんど行わない
- しかし、NFCCファームウェアがパケットを検証する可能性あり

### 2.5 レイヤー5: NFCC Firmware

**推測される動作**:
- NFCCの内部ステートマシンがRF状態を管理
- Listen状態でない場合、データパケットを破棄する可能性
- **これがソフトウェアで回避不可能な可能性のある最大の障壁**

### 2.5 結論

```
[ブロック階層図]

Application Layer
    ↓ (State check may exist)
Java/Kotlin Layer (NfcService)
    ↓ AIDL/JNI
NFA Layer ──────────────── BLOCKING POINT #1
    ↓                      nfa_dm_is_data_exchange_allowed()
NCI Layer ──────────────── BLOCKING POINT #2  
    ↓                      nci_snd_data() state validation
HAL Layer (minimal checks)
    ↓
NFCC Firmware ────────────  POSSIBLE BLOCKING POINT #3
    ↓                       (Hardware state machine)
RF Frontend
```

**主要なブロック要因**: Software State Machine (NFA/NCI層)
**潜在的な最終障壁**: NFCC Firmware

---

## 3. NCIレベルの回避策 (NCI-Level Workarounds)

### Q2への回答: 強制的にパケットを送出する方法はあるか？

### 3.1 アプローチA: 状態偽装 (State Spoofing)

**概念**: 一時的にステート変数を書き換え、TX許可状態に見せかける

```cpp
// 偽装手順
1. nfa_dm_cb.disc_cb.disc_state を NFA_DM_RFST_LISTEN_ACTIVE (0x05) に変更
2. NFA_SendRawFrame() または nci_snd_data() を呼び出し
3. 元の状態 (NFA_DM_RFST_DISCOVERY) に復元
```

**利点**:
- 正規APIを使用するため、パケット構築が正確
- 複数のチェック関数を一度にバイパス

**リスク**:
- 他のスレッドがステート変更を検知する可能性
- NFCCが実際のRF状態と不一致を検出する可能性

### 3.2 アプローチB: 関数フック (Function Hooking)

**概念**: 状態チェック関数をフックし、常にtrueを返すように変更

```cpp
// Target functions to hook
1. nfa_dm_is_data_exchange_allowed() → always return true
2. nci_snd_data() の state check → bypass
```

**利点**:
- グローバル変数を直接操作しないため安全
- 特定の条件下でのみバイパスを有効化可能

**リスク**:
- 複数の関数をフックする必要があり、抜け漏れの可能性

### 3.3 アプローチC: HAL直接書き込み (Direct HAL Write)

**概念**: NFA/NCI層をすべてバイパスし、HAL層に直接パケットを送信

```cpp
// 手順
1. libnfc-nci.so から nfc_hal_entry ポインタを取得
2. NCI Data Packet を手動構築
3. nfc_hal_entry->write() を直接呼び出し
```

**パケット構築例**:
```cpp
uint8_t nci_pkt[32];
uint8_t* p = nci_pkt;

// NCI Data Header
*p++ = 0x00;  // conn_id = Static RF Connection
*p++ = 0x00;  // credits
*p++ = 17;    // payload length

// SENSF_RES Payload
*p++ = 17;    // Length
*p++ = 0x01;  // Response Code
// IDm (8 bytes)
memcpy(p, custom_idm, 8); p += 8;
// PMm (8 bytes)  
memcpy(p, custom_pmm, 8); p += 8;

// Send via HAL
nfc_hal_entry->write(p - nci_pkt, nci_pkt);
```

**利点**:
- ソフトウェア状態チェックを完全にバイパス
- 最も低レベルでの介入

**リスク**:
- NFCCファームウェアが拒否する可能性
- 不正なパケットがシステムを不安定化させる可能性

### 3.4 アプローチD: ベンダー固有コマンド (Vendor-Specific Commands)

**概念**: NFCCベンダーが提供する拡張コマンドを利用

NXP PN553/PN557の例:
```cpp
// Vendor-Specific OID for raw RF frame
#define NXP_PROP_OID_RAW_RF 0x3F

tNCI_STATUS send_raw_rf(uint8_t* data, uint16_t len) {
    uint8_t cmd[256];
    cmd[0] = NCI_RF_TECHNOLOGY_F;  // NFC-F
    memcpy(&cmd[1], data, len);
    return nci_snd_vs_cmd(NXP_PROP_OID_RAW_RF, cmd, len + 1);
}
```

**利点**:
- ベンダーがサポートしている場合、正規の経路
- ファームウェアレベルでの許可がある可能性

**リスク**:
- デバイス依存（Pixel = Samsung/Qualcomm NFC チップ）
- 非公開APIのため動作保証なし

### 3.5 推奨アプローチの優先順位

1. **アプローチA + B の組み合わせ** (状態偽装 + 関数フック)
   - 最も成功確率が高い
   - 実装が比較的容易

2. **アプローチC** (HAL直接書き込み)
   - NFCCが受け入れるか検証必要
   - バックアップ策として準備

3. **アプローチD** (ベンダー固有)
   - チップベンダーの調査が必要
   - 長期的なソリューションとして検討

---

## 4. 具体的な実装アプローチ (Implementation Approach)

### Q3への回答: Frida/Native Hookで制限を突破する具体的手法

### 4.1 フック対象関数

| 関数名 | ファイル | 役割 | フック方法 |
|--------|----------|------|------------|
| `nfa_dm_is_data_exchange_allowed` | nfa_dm_discover.cc | 状態チェック | Return true |
| `NFA_SendRawFrame` | nfa_t3t.cc | Raw frame送信 | パラメータ検証をバイパス |
| `nci_snd_data` | nci_hmsgs.cc | NCIデータ送信 | 状態チェックをスキップ |
| `nfc_ncif_send_data` | nci_hmsgs.cc | 低レベルデータ送信 | 直接呼び出し |

### 4.2 グローバル変数の操作対象

| 変数名 | 構造体 | フィールド | 期待値 |
|--------|--------|----------|--------|
| `nfa_dm_cb` | tNFA_DM_CB | disc_cb.disc_state | 0x05 (LISTEN_ACTIVE) |
| `nfc_cb` | tNFC_CB | nfc_state | 0x05 (NFC_STATE_OPEN) |

### 4.3 シンボル名の特定方法

```bash
# libnfc-nci.so のシンボルダンプ
adb shell "cat /proc/$(pidof com.android.nfc)/maps | grep libnfc"
adb pull /system/lib64/libnfc-nci.so

# シンボル検索
nm -C libnfc-nci.so | grep -E "(nfa_dm|nci_snd|SendRaw)"

# 期待される出力例:
# 00012340 T _ZN3nfa2dm26is_data_exchange_allowedEv
# 00014560 T NFA_SendRawFrame
# 00018900 T nci_snd_data
```

### 4.4 メモリパターン検索

シンボルが難読化されている場合のパターン検索:

```javascript
// nfa_dm_cb 構造体の特定
// disc_state は先頭から数バイトの位置にある
// NFA_DM_RFST_DISCOVERY (0x01) を検索

const pattern = "01 00 00 00";  // disc_state = DISCOVERY
const matches = Memory.scanSync(libnfc.base, libnfc.size, pattern);
```

---

## 5. フック対象関数一覧

### 5.1 必須フック

```cpp
// Function 1: State check bypass
bool nfa_dm_is_data_exchange_allowed(void);
// Location: libnfc-nci.so
// Symbol: _ZN3nfa2dm26is_data_exchange_allowedEv (mangled)
// Action: Return true unconditionally

// Function 2: Raw frame transmission
tNFA_STATUS NFA_SendRawFrame(uint8_t* p_raw_data, uint16_t data_len,
                              uint16_t presence_check_start_delay);
// Location: libnfc-nci.so
// Symbol: NFA_SendRawFrame
// Action: Bypass state validation, call internal send
```

### 5.2 オプションフック

```cpp
// Function 3: NCI data send
tNCI_STATUS nci_snd_data(uint8_t conn_id, BT_HDR* p_buf);
// Action: Bypass conn_id validation

// Function 4: HAL write (for direct approach)
int (*write)(uint16_t data_len, uint8_t* p_data);
// Location: nfc_hal_entry structure
// Action: Direct call with crafted NCI packet
```

---

## 6. Fridaスクリプト例

### 6.1 基本的な状態偽装スクリプト

```javascript
// observe_mode_bypass.js
// Frida script to bypass Observe Mode TX blocking

const LIBNFC = "libnfc-nci.so";

// State constants
const NFA_DM_RFST_DISCOVERY = 0x01;
const NFA_DM_RFST_LISTEN_ACTIVE = 0x05;

// Find nfa_dm_cb global variable
function findNfaDmCb() {
    const libnfc = Process.findModuleByName(LIBNFC);
    if (!libnfc) {
        console.error("[-] libnfc-nci.so not found");
        return null;
    }
    
    // Search for nfa_dm_cb symbol
    const symbols = Module.enumerateSymbols(LIBNFC);
    for (const sym of symbols) {
        if (sym.name.includes("nfa_dm_cb")) {
            console.log("[+] Found nfa_dm_cb at: " + sym.address);
            return sym.address;
        }
    }
    
    console.log("[-] nfa_dm_cb symbol not found, using pattern search...");
    return null;
}

// Hook nfa_dm_is_data_exchange_allowed
function hookStateCheck() {
    const libnfc = Process.findModuleByName(LIBNFC);
    const symbols = Module.enumerateSymbols(LIBNFC);
    
    for (const sym of symbols) {
        if (sym.name.includes("is_data_exchange_allowed") || 
            sym.name.includes("data_exchange")) {
            
            console.log("[+] Hooking: " + sym.name + " at " + sym.address);
            
            Interceptor.attach(sym.address, {
                onEnter: function(args) {
                    console.log("[*] is_data_exchange_allowed called");
                },
                onLeave: function(retval) {
                    console.log("[*] Original return: " + retval);
                    retval.replace(1);  // Force return true
                    console.log("[*] Modified return: 1 (allowed)");
                }
            });
            return true;
        }
    }
    return false;
}

// Hook NFA_SendRawFrame
function hookSendRawFrame() {
    const sendRawFrame = Module.findExportByName(LIBNFC, "NFA_SendRawFrame");
    
    if (sendRawFrame) {
        console.log("[+] Found NFA_SendRawFrame at: " + sendRawFrame);
        
        Interceptor.attach(sendRawFrame, {
            onEnter: function(args) {
                const data = args[0];
                const len = args[1].toInt32();
                console.log("[*] NFA_SendRawFrame called, len=" + len);
                console.log("[*] Data: " + hexdump(data, { length: len }));
            },
            onLeave: function(retval) {
                console.log("[*] NFA_SendRawFrame returned: " + retval);
            }
        });
    } else {
        console.log("[-] NFA_SendRawFrame not found");
    }
}

// State spoofing function
function spoofListenActiveState(nfaDmCbAddr) {
    if (!nfaDmCbAddr) return;
    
    // disc_state offset (may vary by build)
    const DISC_STATE_OFFSET = 0x00;  // Adjust based on structure analysis
    
    const discStatePtr = nfaDmCbAddr.add(DISC_STATE_OFFSET);
    const originalState = discStatePtr.readU8();
    
    console.log("[*] Original disc_state: " + originalState);
    
    // Temporarily set to LISTEN_ACTIVE
    discStatePtr.writeU8(NFA_DM_RFST_LISTEN_ACTIVE);
    console.log("[*] Spoofed disc_state to LISTEN_ACTIVE (0x05)");
    
    return originalState;
}

// Restore original state
function restoreState(nfaDmCbAddr, originalState) {
    if (!nfaDmCbAddr) return;
    
    const DISC_STATE_OFFSET = 0x00;
    const discStatePtr = nfaDmCbAddr.add(DISC_STATE_OFFSET);
    
    discStatePtr.writeU8(originalState);
    console.log("[*] Restored disc_state to: " + originalState);
}

// Build SENSF_RES packet
function buildSensfRes(idm, pmm) {
    const buf = Memory.alloc(19);
    let offset = 0;
    
    buf.add(offset++).writeU8(18);    // Length (excluding length byte)
    buf.add(offset++).writeU8(0x01);  // Response Code
    
    // IDm (8 bytes)
    for (let i = 0; i < 8; i++) {
        buf.add(offset++).writeU8(idm[i]);
    }
    
    // PMm (8 bytes)
    for (let i = 0; i < 8; i++) {
        buf.add(offset++).writeU8(pmm[i]);
    }
    
    return buf;
}

// Main injection function
function injectSensfRes(idm, pmm) {
    console.log("[*] Starting SENSF_RES injection...");
    
    const nfaDmCb = findNfaDmCb();
    const originalState = spoofListenActiveState(nfaDmCb);
    
    const sensfRes = buildSensfRes(idm, pmm);
    
    // Attempt to send via NFA_SendRawFrame
    const sendRawFrame = Module.findExportByName(LIBNFC, "NFA_SendRawFrame");
    if (sendRawFrame) {
        const NFA_SendRawFrame = new NativeFunction(sendRawFrame, 
            'uint8', ['pointer', 'uint16', 'uint16']);
        
        const result = NFA_SendRawFrame(sensfRes, 18, 0);
        console.log("[*] NFA_SendRawFrame result: " + result);
    }
    
    // Restore state
    if (nfaDmCb && originalState !== undefined) {
        restoreState(nfaDmCb, originalState);
    }
}

// Initialization
console.log("===========================================");
console.log("  Observe Mode SENSF_RES Injection Script");
console.log("===========================================");

hookStateCheck();
hookSendRawFrame();

// Export injection function
rpc.exports = {
    inject: function(idmHex, pmmHex) {
        const idm = hexToBytes(idmHex);
        const pmm = hexToBytes(pmmHex);
        injectSensfRes(idm, pmm);
    }
};

function hexToBytes(hex) {
    const bytes = [];
    for (let i = 0; i < hex.length; i += 2) {
        bytes.push(parseInt(hex.substr(i, 2), 16));
    }
    return bytes;
}
```

### 6.2 使用方法

```bash
# Fridaの起動
frida -U -f com.android.nfc -l observe_mode_bypass.js --no-pause

# Python からの呼び出し
import frida

device = frida.get_usb_device()
session = device.attach("com.android.nfc")
script = session.create_script(open("observe_mode_bypass.js").read())
script.load()

# SENSF_RES injection
# IDm: 02FE010203040506
# PMm: 00F0FFD2FE1F1F00
script.exports.inject("02FE010203040506", "00F0FFD2FE1F1F00")
```

---

## 7. 制限事項と考慮点

### 7.1 タイミング制約

- FeliCa仕様: 2.4ms以内の応答が要求
- Hostからの応答は100ms以上のレイテンシが予想される
- **緩和策**: リーダーの再送メカニズムを活用（確率的成功）

### 7.2 NFCCファームウェアの壁

- ソフトウェアバイパスが成功しても、NFCCファームウェアがパケットを破棄する可能性
- ファームウェアの内部状態機構は非公開で変更不可
- **検証方法**: HAL書き込み後のレスポンス有無を確認

### 7.3 デバイス依存性

- NFCチップベンダーによりファームウェア動作が異なる
- Pixel: おそらくSTMicroelectronics ST21NFCD または NXP SN1xx
- ベンダー固有のバイパス方法が存在する可能性

### 7.4 セキュリティ上の懸念

本研究は純粋に技術調査を目的としています：

- ✅ セキュリティサーフェス調査
- ✅ プロトコル理解の深化
- ❌ 攻撃目的での利用

### 7.5 成功確率の見積もり

| アプローチ | ソフトウェアバイパス成功率 | 最終的なRF送信成功率 |
|-----------|-------------------------|---------------------|
| 状態偽装 + 関数フック | 80-90% | 30-50% (FW依存) |
| HAL直接書き込み | 95% | 20-40% (FW依存) |
| ベンダー固有コマンド | 50% (要調査) | 60-80% (正規経路の場合) |

**注**: 最終的なRF送信成功率はNFCCファームウェアの動作に強く依存します。実機検証が必要です。

---

## 付録

### A. 関連AOSPソースコードパス

```
system/nfc/
├── src/
│   ├── nfc/
│   │   ├── nci/
│   │   │   ├── nci_hmsgs.cc      # NCI command/data send
│   │   │   └── nci_hrcv.cc       # NCI notification handling
│   │   ├── nfa/
│   │   │   ├── nfa_dm_discover.cc # Discovery state machine
│   │   │   └── nfa_t3t.cc        # T3T/FeliCa handling
│   │   └── include/
│   │       ├── nci_defs.h        # NCI definitions
│   │       ├── nfa_dm_int.h      # NFA internals
│   │       └── nfc_hal_api.h     # HAL interface
│   └── hal/
│       └── nfc_hal_nci.cc        # HAL implementation

packages/apps/Nfc/
├── src/
│   └── com/android/nfc/
│       ├── NfcService.java       # Main NFC service
│       └── cardemulation/
│           └── HostNfcFService.java # HCE-F base
```

### B. NCI仕様書参照

- NFC Controller Interface (NCI) Technical Specification 2.2
- NFC Forum Type 3 Tag Operation Specification
- JIS X 6319-4 (FeliCa specification)

### C. 参考文献

- AOSP Source: https://android.googlesource.com/platform/system/nfc/
- NFC Forum Specifications: https://nfc-forum.org/
- Android NFC Developer Guide: https://developer.android.com/develop/connectivity/nfc

---

*ドキュメント作成日: 2024年12月*
*対象: Android 14/15, libnfc-nci, Observe Mode*
