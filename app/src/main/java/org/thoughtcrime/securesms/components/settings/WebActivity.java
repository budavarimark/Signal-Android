package org.thoughtcrime.securesms.components.settings;

import android.Manifest;
import android.annotation.SuppressLint;
import android.app.Activity;
import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.webkit.WebSettings;
import android.webkit.WebView;

import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;

import org.thoughtcrime.securesms.R;

public class WebActivity extends Activity {

    private WebView mWebView;

    @Override
    @SuppressLint("SetJavaScriptEnabled")
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        checkPermission(Manifest.permission.INTERNET, 1);
        checkPermission(Manifest.permission.ACCESS_NETWORK_STATE, 1);
        setContentView(R.layout.activity_web);
        mWebView = findViewById(R.id.activity_web_webview);
        WebSettings webSettings = mWebView.getSettings();
        webSettings.setJavaScriptEnabled(true);
        mWebView.setWebViewClient(new MyWebViewClient() {
            public void onPageFinished(WebView view, String url) {
                /*if (url.equals("")) {
                    setResult(Activity.RESULT_OK);
                    finish();
                }*/
            }
        });

        mWebView.addJavascriptInterface(new WebAppInterface(this), "NativeAndroid");

        // LOCAL RESOURCE
        mWebView.loadUrl("file:///android_asset/web/index.html");
    }

    @Override
    public void onBackPressed() {
        if(mWebView.canGoBack()) {
            mWebView.goBack();
        } else {
            super.onBackPressed();
        }
    }

    public void checkPermission(String permission, int requestCode)
    {
        // Checking if permission is not granted
        if (ContextCompat.checkSelfPermission(WebActivity.this, permission) == PackageManager.PERMISSION_DENIED) {
            ActivityCompat.requestPermissions(WebActivity.this, new String[] { permission }, requestCode);
        }

    }
}
