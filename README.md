# hcefhoook - Android NFC Observe Mode Research

## 概要 (Overview)

このリポジトリは、Android 15のNFC Observe Modeにおける**Host-based Raw SENSF_RES Injection**の技術的実現可能性を調査するための研究プロジェクトです。

## 研究目的

通常のAndroid HCE-F (Host Card Emulation)では、`SystemCode = 0xFFFF`（ワイルドカード）のポーリングに対し、eSE (Secure Element)が自動的に固定IDmを返信してしまい、Host側での制御が困難です。

本研究では：
1. **Observe Mode**を使用してeSEを沈黙させる
2. Host側で`SENSF_REQ`を検知後、独自の`SENSF_RES`を強制送信する

という手法の技術的可能性を検討します。

## リポジトリ構成

```
hcefhoook/
├── README.md                    # This file
├── docs/
│   ├── TECHNICAL_ANALYSIS.md    # 詳細な技術分析
│   └── HOOK_TARGETS.md          # フック対象関数リファレンス
└── ref_aosp/
    ├── system_nfc/              # AOSP system/nfc 参照コード
    │   └── src/nfc/
    │       ├── nci/
    │       │   ├── nci_hmsgs.cc    # NCI command/data functions
    │       │   └── nci_hrcv.cc     # NCI notification handling
    │       ├── nfa/
    │       │   ├── nfa_dm_discover.cc  # Discovery state machine
    │       │   └── nfa_t3t.cc      # NFC-F/T3T handling
    │       └── include/
    │           ├── nci_defs.h      # NCI protocol definitions
    │           ├── nfa_dm_int.h    # NFA internal structures
    │           └── nfc_hal_api.h   # HAL interface
    └── packages_apps_nfc/        # AOSP packages/apps/Nfc 参照コード
        └── src/
            └── NfcObserveMode.java  # Observe Mode documentation
```

## 主要な調査結果

### ブロック要因の特定

データ送信は以下の階層でブロックされています：

1. **NFA Layer**: `nfa_dm_is_data_exchange_allowed()` が状態をチェック
2. **NCI Layer**: `nci_snd_data()` が接続状態を検証
3. **NFCC Firmware**: ハードウェアステートマシン（ソフトウェアで制御不可）

### 提案するバイパス手法

1. **状態偽装 (State Spoofing)**: `nfa_dm_cb.disc_cb.disc_state`を一時的に`LISTEN_ACTIVE`に変更
2. **関数フック**: `nfa_dm_is_data_exchange_allowed()`を常にtrueを返すようにフック
3. **HAL直接書き込み**: NCI/NFA層をバイパスしてHALに直接書き込み

詳細は [TECHNICAL_ANALYSIS.md](docs/TECHNICAL_ANALYSIS.md) を参照してください。

## 必要な環境

- **デバイス**: Google Pixel (Android 14/15)
- **権限**: Root権限取得済み
- **ツール**: Frida, Xposed/LSPosed, Native Hooking Library (Dobby等)

## 参考資料

- [AOSP system/nfc](https://android.googlesource.com/platform/system/nfc/)
- [AOSP packages/apps/Nfc](https://android.googlesource.com/platform/packages/apps/Nfc/)
- NFC Controller Interface (NCI) Technical Specification 2.2
- JIS X 6319-4 (FeliCa specification)

## ⚠️ 注意事項

本研究は**純粋に技術調査・セキュリティサーフェス調査**を目的としています。悪意のある攻撃目的での使用は意図していません。

## ライセンス

参照コードはApache License 2.0に基づきます（AOSP由来）
