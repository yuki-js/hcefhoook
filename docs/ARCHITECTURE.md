# Architecture Overview

## プロセス分離とIPC設計 (Process Isolation and IPC Design)

本プロジェクトは2つの異なるプロセスで動作するコードから構成されています。これらのプロセス間でデータを共有するには、Androidが提供するIPC（プロセス間通信）メカニズムを使用する必要があります。

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         Android System                                    │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌──────────────────────────┐     ┌──────────────────────────────────┐ │
│  │    App Process           │     │    com.android.nfc Process       │ │
│  │ (app.aoki.yuki.hcefhook)│     │    (System NFC Service)          │ │
│  │                          │     │                                   │ │
│  │  ┌────────────────────┐ │     │  ┌─────────────────────────────┐ │ │
│  │  │    MainActivity    │ │     │  │      Xposed Hooks          │ │ │
│  │  │   - UI Display     │ │     │  │   - PollingFrameHook       │ │ │
│  │  │   - Configuration  │ │     │  │   - NfaStateHook           │ │ │
│  │  │   - Injection      │ │     │  │   - SendRawFrameHook       │ │ │
│  │  └─────────┬──────────┘ │     │  └───────────┬─────────────────┘ │ │
│  │            │            │     │              │                   │ │
│  │  ┌─────────▼──────────┐ │     │  ┌───────────▼───────────────┐   │ │
│  │  │   HookIpcProvider  │◄├─────┼──┤      IpcClient            │   │ │
│  │  │  (ContentProvider) │ │     │  │  (ContentResolver)        │   │ │
│  │  └─────────┬──────────┘ │     │  └───────────────────────────┘   │ │
│  │            │            │     │                                   │ │
│  │  ┌─────────▼──────────┐ │     │  ┌───────────────────────────┐   │ │
│  │  │    LogReceiver     │◄├─────┼──┤    LogBroadcaster         │   │ │
│  │  │(BroadcastReceiver) │ │     │  │  (sendBroadcast)          │   │ │
│  │  └────────────────────┘ │     │  └───────────────────────────┘   │ │
│  │                          │     │                                   │ │
│  └──────────────────────────┘     └──────────────────────────────────┘ │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

## IPC通信フロー

### 1. App → Hook (設定の送信)

```
MainActivity                    HookIpcProvider               IpcClient (in Hook)
    │                               │                               │
    │  insert(config, values)       │                               │
    │──────────────────────────────►│                               │
    │                               │  (stored in configMap)        │
    │                               │                               │
    │                               │       query(config/key)       │
    │                               │◄──────────────────────────────│
    │                               │       cursor with value       │
    │                               │──────────────────────────────►│
```

### 2. Hook → App (ログ・イベント通知)

```
XposedHook                    LogBroadcaster                LogReceiver
    │                               │                            │
    │  broadcaster.info(msg)        │                            │
    │──────────────────────────────►│                            │
    │                               │  sendBroadcast(intent)     │
    │                               │───────────────────────────►│
    │                               │                            │ onReceive()
    │                               │                            │ callback.onLog()
```

### 3. Manual Injection Flow

```
User clicks "Inject"
        │
        ▼
MainActivity.queueManualInjection()
        │
        ▼
IpcClient.queueInjection(sensfRes)
        │
        ▼
ContentProvider.insert(injection_queue)
        │
        ▼
(Stored in injectionQueue)
        │
        ▼
Hook polls ContentProvider for pending injections
        │
        ▼
SendRawFrameHook.attemptInjection()
```

## コンポーネント詳細

### MainActivity (UI Layer)
- ユーザーインターフェースの表示
- IDm/PMm設定の入力
- ログの表示
- 手動インジェクションのトリガー
- 自動インジェクション/バイパスの有効化

### HookIpcProvider (IPC Layer - App Process)
- ContentProviderとしてアプリプロセスで動作
- 設定データの永続化
- インジェクションキューの管理
- フックプロセスからのクエリに応答

### IpcClient (IPC Layer - Hook Process)
- ContentResolverを使用してProviderにアクセス
- 設定の読み書き
- ペンディングインジェクションの取得

### LogBroadcaster (IPC Layer - Hook Process)
- Broadcastを使用してログメッセージを送信
- SENSF検出イベントの通知

### LogReceiver (IPC Layer - App Process)
- BroadcastReceiverとしてログを受信
- MainActivityにコールバック

### Xposed Hooks (Hook Layer)
- **PollingFrameHook**: ポーリングフレームの検出
- **NfaStateHook**: NFA状態のバイパス
- **SendRawFrameHook**: SENSF_RES送信の実行

## 重要な注意事項

### 1. 参照の共有不可
異なるプロセス間でJavaオブジェクトの参照を直接共有することはできません。すべてのデータはシリアライズ（Intent extras、Cursor、ContentValues）して渡す必要があります。

### 2. タイミングの問題
ContentProviderへのアクセスは同期的ですが、Broadcastは非同期です。時間に依存する操作では注意が必要です。

### 3. パーミッション
ContentProviderは `exported="true"` で公開していますが、本番環境では適切なパーミッション保護を追加してください。

### 4. プロセスライフサイクル
- フックプロセス（com.android.nfc）はシステムサービスとして常時稼働
- アプリプロセスはユーザーがアプリを開いたときのみ稼働
- フックはアプリプロセスが停止していてもログを送信し続ける（受信されない）
