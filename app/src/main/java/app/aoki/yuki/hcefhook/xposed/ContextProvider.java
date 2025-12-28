package app.aoki.yuki.hcefhook.xposed;

import android.content.Context;

/**
 * Interface for providing Context to hooks
 * Context may be resolved lazily after Application.attach() is called
 */
public interface ContextProvider {
    Context getContext();
}
