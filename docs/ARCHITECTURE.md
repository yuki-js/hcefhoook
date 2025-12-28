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
- **ObserveModeManager初期化**: アプリ起動時にObserve Modeマネージャーを初期化
- **SENSF_REQコールバック登録**: 検出時の自動応答処理を設定

### ObserveModeManager (Observe Mode Layer)
- **NFCC Observe Mode制御**: NativeNfcManager経由でObserve Modeの有効化/無効化
- **ポーリングフレーム解析**: NCI_ANDROID_POLLING_FRAME_NTFからSENSF_REQを検出
- **eSE沈黙化**: Observe Mode有効時にeSEの自動応答を抑止
- **コールバック管理**: SENSF_REQ検出時のアプリケーション層への通知
- **状態管理**: Observe Modeのアクティブ状態を追跡

### SprayController (Spray Mode Layer)
- **連続送信制御**: 2ms間隔でSENSF_RESを最大10回送信
- **タイミング調整**: Handler + Runnableベースのスケジューリング
- **確率的成功戦略**: FeliCaの厳密な2.4ms制約を満たせないため、統計的アプローチで対応
- **State Bypass連携**: NfaStateHookおよびDobbyHooksと連携して送信制約を回避
- **NativeNfcManager参照**: doTransceive()メソッドを直接呼び出して送信

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
- **PollingFrameHook**: ポーリングフレームの検出、ObserveModeManagerへの転送
- **NfaStateHook**: NFA状態のバイパス
- **SendRawFrameHook**: SENSF_RES送信の実行、SprayControllerの統合
- **NativeHooks (Dobby)**: ネイティブ層でのnfa_dm_cbアクセスと状態操作

## 統合フロー (Integration Flow)

### Complete SENSF_REQ Detection → Response Flow

```
1. User Action
   MainActivity.onCreate()
      │
      ├─► ObserveModeManager.initialize(context)
      │      │
      │      └─► NfcAdapter取得
      │          NativeNfcManager参照取得 (reflection)
      │          Observe Mode制御メソッドのキャッシュ
      │
      └─► ObserveModeManager.setSensfReqCallback((reqData, sc) -> {...})
             │
             └─► コールバック登録完了

2. Observe Mode Activation (Option A: MainActivity UI button)
   MainActivity: observeModeToggleButton.click()
      │
      └─► ObserveModeManager.enableObserveMode()
             │
             ├─► Method 1: enableObserveModeMethod.invoke(nativeNfcManager, true)
             ├─► Method 2: doEnableDiscovery(..., enableObserve=true)
             └─► Method 3: NfcAdapter.isEnabled() (fallback)

3. リーダーからSENSF_REQ送信
   Reader sends SENSF_REQ (SC=FFFF)
      │
      └─► NFCC receives in Observe Mode
             │
             └─► eSE is silenced (no auto-response)
                    │
                    └─► NFCC sends NCI_ANDROID_POLLING_FRAME_NTF to Host

4. Xposed Hook Detection (android.nfc process)
   NfcService.onPollingLoopDetected(frameData)
      │
      └─► PollingFrameHook.processPollingFrame(frameData, broadcaster)
             │
             ├─► CRITICAL INTEGRATION POINT 1:
             │   ObserveModeManager.onPollingFrameReceived(frameData)
             │      │
             │      ├─► Parse frameData: check if SENSF_REQ (cmd=0x00)
             │      ├─► Extract SystemCode: (frameData[2] << 8) | frameData[3]
             │      ├─► Log detection: "*** SENSF_REQ DETECTED ***"
             │      │
             │      └─► IF systemCode == 0xFFFF:
             │             │
             │             └─► sensfReqCallback.onSensfReqDetected(frameData, systemCode)
             │
             └─► LEGACY: triggerSensfResInjection(broadcaster, context)
                    │
                    └─► IpcClient.isAutoInjectEnabled()
                           │
                           └─► SendRawFrameHook.injectSensfRes(sensfRes)

5. Callback Execution (app process, via registered callback)
   ObserveModeManager callback fires
      │
      └─► MainActivity: runOnUiThread(() -> {
             │
             ├─► appendLog("DETECT", "*** SENSF_REQ Detected ***")
             ├─► Toast.makeText("SENSF_REQ SC=0xFFFF")
             │
             └─► IF autoInjectCheck.isChecked():
                    │
                    ├─► Build SENSF_RES from IDm/PMm inputs
                    │      new SensfResBuilder().setIdm(idm).setPmm(pmm).build()
                    │
                    ├─► IF sprayModeCheck.isChecked():
                    │      ipcClient.queueInjection(sensfRes)  // Spray mode
                    │      └─► Hook will use SprayController
                    │
                    └─► ELSE:
                           ipcClient.queueInjection(sensfRes)  // Single-shot
                           └─► Hook will use single injection

6. Hook-side Injection (android.nfc process)
   SendRawFrameHook.injectSensfRes(sensfRes)
      │
      ├─► CRITICAL INTEGRATION POINT 2:
      │   Check if DobbyHooks.isSprayModeEnabled()
      │      │
      │      └─► IF true:
      │             SprayController.startSpray(sensfRes)
      │                │
      │                ├─► NfaStateHook.spoofListenActiveState()
      │                ├─► DobbyHooks.enableSprayMode()
      │                │
      │                └─► Handler.postDelayed every 2ms:
      │                       performTransmission()
      │                          │
      │                          └─► nativeNfcManagerInstance.doTransceive(sensfRes)
      │                                 │
      │                                 └─► NFCC sends RF frame
      │                                        │
      │                                        └─► Reader receives (probabilistic)
      │
      └─► ELSE (single-shot mode):
             attemptInjection()
                │
                ├─► NfaStateHook.spoofListenActiveState()
                │
                └─► transceiveMethod.invoke(nativeNfcManager, sensfRes)
                       │
                       └─► NFCC sends RF frame
                              │
                              └─► Reader receives

7. Transmission via Native Layer
   NativeNfcManager.doTransceive(sensfRes, false, responseLen)
      │
      └─► JNI: nativeNfcManager_doTransceive()
             │
             └─► nfa_dm_act_send_raw_frame() [Symbol 0x14e070]
                    │
                    ├─► IF DobbyHooks active:
                    │      nfa_dm_cb manipulation to bypass state checks
                    │
                    └─► NCI_SendData()
                           │
                           └─► HAL_WRITE()
                                  │
                                  └─► NFCC RF transmission

8. Success/Failure Handling
   SprayController transmission loop
      │
      ├─► Count transmissions (max 10)
      ├─► Log every 3rd transmission
      ├─► Stop after 20ms or max transmissions
      │
      └─► SprayController.stopSpray()
             │
             ├─► NfaStateHook.restoreState()
             ├─► DobbyHooks.disableSprayMode()
             └─► Log: "*** SPRAY MODE STOPPED *** Total transmissions: N"
```

### Critical Integration Points Summary

1. **PollingFrameHook → ObserveModeManager** (Line 211 in PollingFrameHook.java)
   - `ObserveModeManager.onPollingFrameReceived(frameData)` called
   - ObserveModeManager parses and detects SENSF_REQ
   - Callback triggers if SystemCode matches

2. **MainActivity → ObserveModeManager** (Line 89 in MainActivity.java)
   - `ObserveModeManager.initialize(this)` in onCreate()
   - `ObserveModeManager.setSensfReqCallback(...)` registers callback
   - Callback prepares and queues SENSF_RES via IPC

3. **SendRawFrameHook → SprayController** (Line 63 in SendRawFrameHook.java)
   - Check `DobbyHooks.isSprayModeEnabled()`
   - If true: `SprayController.startSpray(sensfRes)`
   - If false: Single-shot `attemptInjection()`

4. **SendRawFrameHook → NativeNfcManager** (Line 188 in SendRawFrameHook.java)
   - `cacheTransceiveMethod()` stores transceive method reference
   - `SprayController.setNativeNfcManager(instance, method)`
   - SprayController can now call doTransceive directly

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
