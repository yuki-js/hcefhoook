# 残作業リスト (Remaining Critical Work)

## 背理法による自己批判分析

「私の実装には致命的な欠陥がある」という前提で検証した結果、以下の重大な問題が発見されました：

## 🔴 CRITICAL: 即座に修正が必要な欠陥

### 1. PollingFrameHook → ObserveModeManager 接続が未完成
**問題**: PollingFrameHookはObserveModeManager.onPollingFrameReceived()を呼び出していない
**影響**: SENSF_REQが検出されてもObserveModeManagerに通知されない
**修正**: processPollingFrame()内でObserveModeManager.onPollingFrameReceived()を呼び出す

### 2. MainActivity → ObserveModeManager 統合が未実装
**問題**: MainActivityがObserveModeManagerを初期化・使用していない  
**影響**: ユーザーがObserve Modeを制御できない
**修正**: MainActivity.onCreate()でObserveModeManager.initialize()を呼び出し、UIボタンで制御

### 3. SendRawFrameHook → SprayController 接続が未完成
**問題**: SendRawFrameHookがSprayControllerを使用していない
**影響**: Spray Modeが動作しない
**修正**: SendRawFrameHook.injectSensfRes()内でSprayController.startSpray()を呼び出す

### 4. 全レイヤーへのログ追加が不完全
**問題**: 以下のクラスにログが不足：
- Constants.java
- SensfResBuilder.java
- IpcClient.java  
- HookIpcProvider.java
- LogReceiver.java
- ContextProvider.java

**修正**: 全メソッドの開始/終了にログを追加

## ⚠️ HIGH PRIORITY: 重要な改善

### 5. ObserveModeManager のコールバック登録
**問題**: MainActivity からコールバックを登録する仕組みがない
**修正**: 
```java
ObserveModeManager.setSensfReqCallback((reqData, systemCode) -> {
    // Spray mode or single-shot injection
    if (autoInject) {
        SprayController.startSpray(sensfRes);
    }
});
```

### 6. SprayController への NativeNfcManager 参照渡し
**問題**: SprayControllerがNativeNfcManagerインスタンスを持っていない
**修正**: SendRawFrameHook がキャプチャしたインスタンスを SprayController.setNativeNfcManager() で渡す

### 7. Native Hooks の実際のフック実装
**問題**: dobby_hooks.cpp は Symbol 解決のみでフックしていない
**影響**: State bypass が動作しない
**解決策**:
- Option A: Dobby prebuilt ライブラリを追加
- Option B: PLT hook を実装
- Option C: nfa_dm_cb の直接メモリ操作（最も安全）

## 📝 MEDIUM PRIORITY: ドキュメント更新

### 8. README.md 更新
- ObserveModeManager の説明追加
- SprayController の説明追加
- KernelSU module の統合説明
- アーキテクチャ図の更新

### 9. SECURITY_SUMMARY.md 作成
- 権限要件（root, KernelSU）
- SELinux への影響
- セキュリティリスク
- 責任ある使用のガイドライン

### 10. TECHNICAL_ANALYSIS.md 更新
- 新しい実装アプローチの説明
- Symbol Analysis 結果の統合
- Observe Mode フローの詳細化

## 🔬 TESTING: 検証が必要な項目

### 11. ビルド検証（Protocol 1）
- [x] First clean build
- [x] Second clean build
- [ ] Third verification build (after remaining fixes)

### 12. ログ出力検証
- [ ] 全クラスのログが logcat に出力されることを確認
- [ ] ログレベル（VERBOSE, DEBUG, INFO, WARN, ERROR）が適切
- [ ] センシティブ情報（IDm/PMm）がログに含まれていないことを確認

### 13. 統合テスト（実機が必要）
- [ ] ObserveModeManager.initialize() 成功
- [ ] ObserveModeManager.enableObserveMode() 成功  
- [ ] SENSF_REQ 検出確認
- [ ] SENSF_RES injection 成功
- [ ] Spray mode 連続送信確認

## 📊 最終確認（Protocol 2: 8-Step Ultrathink Ritual - 続き）

### Check 9/8 (追加): 新要件への適合性
**Timestamp**: 実施待ち
**Vocalization**: "新要件を完全に満たしているか？"
**Check Items**:
- [ ] Symbol Analysis 結果を踏まえた実装
- [ ] Observe Mode 起動ロジック実装
- [ ] SENSF_REQ 検出 → respond フロー実装
- [ ] 全レイヤーへのログ追加

## 実装優先順位

1. ✅ **DONE**: Symbol Analysis, ObserveModeManager, SprayController 作成
2. 🔴 **NOW**: PollingFrameHook → ObserveModeManager 接続
3. 🔴 **NOW**: MainActivity 統合
4. 🔴 **NOW**: SendRawFrameHook → SprayController 接続
5. ⚠️ **NEXT**: 全レイヤーログ追加
6. ⚠️ **NEXT**: ドキュメント更新
7. 🔬 **FINAL**: 実機テスト（ユーザー環境）

## 自己評価（背理法）

「私は正しいことをしている」と仮定すると、以下の矛盾が生じる：
- ObserveModeManager が孤立している → 使用されていない
- SprayController が孤立している → 使用されていない
- ログが不足している → デバッグ不可能

**結論**: 実装は 70% 完了だが、30% の重要な統合作業が未完成。
このまま完了とすることは許されない。残作業を完遂する必要がある。
