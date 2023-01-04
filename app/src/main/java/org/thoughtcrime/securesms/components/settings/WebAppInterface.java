package org.thoughtcrime.securesms.components.settings;

import android.annotation.SuppressLint;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.provider.Settings;
import android.webkit.JavascriptInterface;
import android.widget.Toast;

public class WebAppInterface {
    Context mContext;

    public WebAppInterface(Context mContext){
        this.mContext = mContext;
    }

    @JavascriptInterface
    public void copyToClipboard(String text) {
        ClipboardManager clipboard = (ClipboardManager) mContext.getSystemService(Context.CLIPBOARD_SERVICE);
        ClipData         clip      = ClipData.newPlainText("code", text);
        clipboard.setPrimaryClip(clip);

        Toast.makeText(mContext, "Másolva", Toast.LENGTH_SHORT).show();
    }

    @SuppressLint("HardwareIds") @JavascriptInterface
    public String getOwnCode() {
        if(android.os.Build.VERSION.SDK_INT >= 26) {
            return Settings.Secure.getString(mContext.getContentResolver(), Settings.Secure.ANDROID_ID);
        }else{
            return "Nem támogatott eszköz: Minimum Android 8 szükséges";
        }
    }
}