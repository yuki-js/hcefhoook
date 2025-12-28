# Usage Guide / 使用ガイド

## 概要

本ツールは、Android NFC Observe Modeにおける SENSF_RES インジェクションを実現するためのPoCです。

## 前提条件

### 必要なもの
- Google Pixel (Android 14/15) または同等のNFC対応デバイス
- Root権限
- LSPosed Framework (または互換フレームワーク)
- ADB環境

### 対象
- NFC-F (FeliCa) プロトコル
- SystemCode = 0xFFFF (ワイルドカード) のポーリング

## インストール手順

### 1. APKのインストール

```bash
# デバッグビルドのインストール
adb install app/build/outputs/apk/debug/app-debug.apk
```

### 2. LSPosedでの有効化

1. LSPosedマネージャーを開く
2. モジュール一覧から "HCE-F Hook" を選択
3. モジュールを有効化
4. スコープに `com.android.nfc` を追加
5. デバイスを再起動

### 3. 動作確認

1. HCE-F Hook アプリを起動
2. ステータス表示で "Xposed Hook: Active ✓" を確認
3. ログにフック初期化メッセージが表示されることを確認

## 使用方法

### 基本操作

#### IDm/PMm の設定
```
IDm (8バイト): カードを識別するための一意のID
PMm (8バイト): カードの能力を示すパラメータ

デフォルト値:
- IDm: 1145141919810000
- PMm: FFFFFFFFFFFFFFFF
```

#### Test ボタン
- 入力されたIDm/PMMから SENSF_RES フレームを生成
- フレームの妥当性を検証
- 設定を保存

#### Inject ボタン
- SENSF_RES フレームをインジェクションキューに追加
- 次のポーリング検出時に送信を試行

### 自動インジェクション

"Auto-Inject" チェックボックスを有効にすると:
1. SENSF_REQ (SC=FFFF) が検出されると
2. 自動的に設定されたIDm/PMMで SENSF_RES を生成
3. 即座にインジェクションを試行

### 状態バイパス

"State Bypass" チェックボックスを有効にすると:
- NFA_DM_RFST_DISCOVERY 状態でも送信を試行
- nfa_dm_cb.disc_cb.disc_state をスプーフィング

## Frida スクリプトの使用

より深いネイティブレベルのフックには、Frida スクリプトを使用します。

### Frida のセットアップ

```bash
# Frida サーバーの起動 (デバイス上)
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "/data/local/tmp/frida-server &"
```

### スクリプトの実行

```bash
# NFC サービスにアタッチ
frida -U -n com.android.nfc -l scripts/frida_native_hook.js

# または spawn モード
frida -U -f com.android.nfc -l scripts/frida_native_hook.js --no-pause
```

### Frida RPC コマンド

```javascript
// バイパスの有効化
rpc.exports.enableBypass()

// バイパスの無効化
rpc.exports.disableBypass()

// SENSF_RES のインジェクション
rpc.exports.inject("1145141919810000", "FFFFFFFFFFFFFFFF")

// カスタム IDm/PMm でのインジェクション
rpc.exports.injectCustom("02FE010203040506", "00F0FFD2FE1F1F00")
```

## トラブルシューティング

### フックが有効にならない

1. LSPosedでモジュールが有効になっているか確認
2. スコープに `com.android.nfc` が含まれているか確認
3. デバイスを再起動
4. Logcat でエラーを確認:
   ```bash
   adb logcat -s HcefHook
   ```

### SENSF_REQ が検出されない

1. Observe Mode が有効になっているか確認
2. リーダーが SC=FFFF でポーリングしているか確認
3. NFC が有効になっているか確認

### インジェクションが成功しない

主な原因:
1. **状態チェック**: Observe Mode では状態が LISTEN_ACTIVE ではないため、NFA層でブロックされる
2. **タイミング**: FeliCa の応答タイムアウト (2.4ms) に間に合わない
3. **NFCC制限**: ファームウェアレベルで TX がブロックされている可能性

対処法:
1. "State Bypass" を有効にする
2. Frida スクリプトでネイティブフックを使用
3. HAL 直接アクセスを試行

## ログの見方

### ログレベル
- **INFO**: 一般情報
- **DEBUG**: デバッグ情報
- **WARN**: 警告
- **ERROR**: エラー
- **DATA**: データダンプ
- **DETECT**: SENSF_REQ 検出
- **CONFIG**: 設定変更

### 典型的なログ出力例

```
[15:23:45.123] INFO: HCE-F Hook PoC started
[15:23:45.125] INFO: Device: Pixel 7 (Android 14)
[15:23:45.130] INFO: Waiting for hook activation...
[15:23:46.500] INFO: HCE-F hooks installed for: com.android.nfc
[15:24:10.234] DETECT: *** SENSF_REQ Detected ***
  SystemCode: 0xFFFF
  Data: 0600FFFF0003
[15:24:10.235] INFO: Prepared SENSF_RES: 11011145141919810000FFFFFFFFFFFFFFFF
[15:24:10.236] WARN: Injection attempt - state bypass required
```

## セキュリティ上の注意

⚠️ **警告**: 本ツールは研究目的のPoCです。

- 悪意のある目的での使用は禁止
- 他者のカードをエミュレートすることは法的問題を引き起こす可能性
- 本番環境での使用は推奨しない
- 自己責任での使用

## 参考資料

- [TECHNICAL_ANALYSIS.md](TECHNICAL_ANALYSIS.md) - 技術的な詳細分析
- [HOOK_TARGETS.md](HOOK_TARGETS.md) - フック対象関数リファレンス
- [ARCHITECTURE.md](ARCHITECTURE.md) - アーキテクチャ設計
