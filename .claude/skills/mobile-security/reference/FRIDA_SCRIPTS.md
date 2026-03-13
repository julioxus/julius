# Common Frida Scripts

## SSL Pinning Bypass

### Android (Universal)

```javascript
Java.perform(function() {
    // TrustManager bypass
    var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
    TrustManagerImpl.verifyChain.implementation = function(untrustedChain, trustAnchorChain,
        host, clientAuth, ocspData, tlsSctData) {
        return untrustedChain;
    };

    // OkHttp CertificatePinner bypass
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List')
            .implementation = function(hostname, peerCertificates) { return; };
    } catch(e) {}
});
```

### iOS (Universal)

```javascript
if (ObjC.available) {
    var SSLSetSessionOption = new NativeFunction(
        Module.findExportByName('Security', 'SSLSetSessionOption'),
        'int', ['pointer', 'int', 'bool']
    );
    Interceptor.replace(SSLSetSessionOption, new NativeCallback(function(ctx, opt, val) {
        if (opt === 0) return SSLSetSessionOption(ctx, opt, 1); // kSSLSessionOptionBreakOnServerAuth
        return SSLSetSessionOption(ctx, opt, val);
    }, 'int', ['pointer', 'int', 'bool']));
}
```

## Root/Jailbreak Detection Bypass

### Android Root Detection

```javascript
Java.perform(function() {
    // Common root check methods
    var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
    RootBeer.isRooted.implementation = function() { return false; };

    // File.exists() bypass for su binary
    var File = Java.use('java.io.File');
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        if (path.indexOf('su') !== -1 || path.indexOf('Superuser') !== -1) return false;
        return this.exists.call(this);
    };
});
```

### iOS Jailbreak Detection

```javascript
if (ObjC.available) {
    // NSFileManager fileExistsAtPath bypass
    var NSFileManager = ObjC.classes.NSFileManager;
    Interceptor.attach(NSFileManager['- fileExistsAtPath:'].implementation, {
        onEnter: function(args) { this.path = ObjC.Object(args[2]).toString(); },
        onLeave: function(retval) {
            if (this.path.indexOf('cydia') !== -1 || this.path.indexOf('substrate') !== -1)
                retval.replace(0);
        }
    });
}
```

## API Call Hooking

### HTTP Request Interception (Android)

```javascript
Java.perform(function() {
    var URL = Java.use('java.net.URL');
    URL.openConnection.overload().implementation = function() {
        var conn = this.openConnection();
        console.log('[HTTP] ' + this.toString());
        return conn;
    };

    // OkHttp interceptor
    var OkHttpClient = Java.use('okhttp3.OkHttpClient');
    OkHttpClient.newCall.implementation = function(request) {
        console.log('[OkHttp] ' + request.url().toString());
        console.log('[OkHttp] Headers: ' + request.headers().toString());
        return this.newCall(request);
    };
});
```

### Crypto Function Hooking

```javascript
Java.perform(function() {
    var Cipher = Java.use('javax.crypto.Cipher');
    Cipher.doFinal.overload('[B').implementation = function(input) {
        console.log('[Crypto] Algorithm: ' + this.getAlgorithm());
        console.log('[Crypto] Input: ' + bytesToHex(input));
        var result = this.doFinal(input);
        console.log('[Crypto] Output: ' + bytesToHex(result));
        return result;
    };

    var SecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
    SecretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function(key, alg) {
        console.log('[Key] Algorithm: ' + alg + ' Key: ' + bytesToHex(key));
        return this.$init(key, alg);
    };
});

function bytesToHex(bytes) {
    var hex = [];
    for (var i = 0; i < bytes.length; i++) hex.push(('0' + (bytes[i] & 0xFF).toString(16)).slice(-2));
    return hex.join('');
}
```

## SharedPreferences / Keychain Monitoring

### Android SharedPreferences

```javascript
Java.perform(function() {
    var SharedPreferencesEditor = Java.use('android.app.SharedPreferencesImpl$EditorImpl');
    SharedPreferencesEditor.putString.implementation = function(key, value) {
        console.log('[SharedPrefs] PUT ' + key + ' = ' + value);
        return this.putString(key, value);
    };
});
```

## Script Injection Workflow

1. **Identify target**: `frida-ps -U` to list processes
2. **Attach**: Via Frida MCP `attach` tool with process name/PID
3. **Load script**: Via `execute_script` or `load_script_file`
4. **Monitor output**: Script `console.log()` appears in Frida MCP response
5. **Iterate**: Modify hooks based on observed behavior
