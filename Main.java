import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.List;
import java.util.Map;

public class Main {
    private static final SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");

    private static void print(String str) {
        String[] lines = str.split("\n");
        for (String line : lines) {
            System.out.println("[" + sdf.format(System.currentTimeMillis()) + "] " + line);
        }
    }

    public static void main(String[] args) throws Exception {
        print("   _____              ___.   .__         _________      .__                     \n" +
                "  /  _  \\   ____  __ _\\_ |__ |__| ______/   _____/ ____ |  |___  __ ___________ \n" +
                " /  /_\\  \\ /    \\|  |  \\ __ \\|  |/  ___/\\_____  \\ /  _ \\|  |\\  \\/ // __ \\_  __ \\\n" +
                "/    |    \\   |  \\  |  / \\_\\ \\  |\\___ \\ /        (  <_> )  |_\\   /\\  ___/|  | \\/\n" +
                "\\____|__  /___|  /____/|___  /__/____  >_______  /\\____/|____/\\_/  \\___  >__|   \n" +
                "        \\/     \\/          \\/        \\/        \\/                      \\/       ");
        final String challengeEndpoint = "https://anubis.techaro.lol/";
        print("[*] Challenge Endpoint: " + challengeEndpoint);
        print("[*] Muting SSL verification...");
        muteSSL();
        print("[+] Fetching challenge phase #1...");
        Result getChallenge = fetch(challengeEndpoint, null);
        print("[+] Solving challenge phase #1...");
        int lIdx = getChallenge.body.indexOf("url=/");
        int rIdx = getChallenge.body.indexOf("\"><", lIdx);
        String middle = getChallenge.body.substring(lIdx + 5, rIdx);
        String getCookieUrl = challengeEndpoint + middle.replace("&amp;", "&");
        Thread.sleep(1000); // Zzz
        print("[+] Fetching challenge phase #2...");
        Result getCookie = fetch(getCookieUrl, getChallenge.cookie);
        print("[+] Solving challenge phase #2...");
        print("[-] No additional computation needed, skipped fetching phase #3...");
        String finalCookie = getChallenge.cookie + "; " + getCookie.cookie;
        print("[+] Solving challenge phase #3...");
        Thread.sleep(1000); // Zzz
        print("[*] All set ;) Use this cookie will kill anubis ↓");
        print(finalCookie);
        print("[*] See it work:");
        Result finalResult = fetch(challengeEndpoint, finalCookie);
        print(finalResult.body);
    }

    private static void muteSSL() throws Exception {
        TrustManager[] trustAllCerts = new TrustManager[]{
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() {
                        return null;
                    }

                    public void checkClientTrusted(X509Certificate[] certs, String authType) {
                    }

                    public void checkServerTrusted(X509Certificate[] certs, String authType) {
                    }
                }
        };

        SSLContext sc = SSLContext.getInstance("SSL");
        sc.init(null, trustAllCerts, new java.security.SecureRandom());
        HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
    }

    private static Result fetch(String url, String cookie) throws Exception {
        HttpURLConnection connection = (HttpURLConnection) new URL(url).openConnection();
        connection.setRequestMethod("GET");
        connection.setInstanceFollowRedirects(false);
        connection.setRequestProperty("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 AnubisSolver/1.0 +https://github.com/huzpsb/anubis_solver");
        connection.setRequestProperty("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8");
        connection.setRequestProperty("Accept-Language", "en-US,en;q=0.5");


        if (cookie != null && !cookie.isEmpty()) {
            connection.setRequestProperty("Cookie", cookie);
        }

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        InputStream is;
        try {
            is = connection.getInputStream();
        } catch (Exception ex) {
            is = connection.getErrorStream();
        }
        int len;
        byte[] buffer = new byte[1024];
        while ((len = is.read(buffer)) != -1) {
            baos.write(buffer, 0, len);
        }
        connection.disconnect();
        String body = baos.toString("UTF-8");

        StringBuilder sb = new StringBuilder();
        Map<String, List<String>> headers = connection.getHeaderFields();
        for (Map.Entry<String, List<String>> entry : headers.entrySet()) {
            if ("Set-Cookie".equalsIgnoreCase(entry.getKey())) {
                for (String cookieValue : entry.getValue()) {
                    String cookiePart = cookieValue.split(";", 2)[0];
                    if (cookiePart.endsWith("=")) {
                        continue;
                    }
                    if (sb.length() > 0) {
                        sb.append("; ");
                    }
                    sb.append(cookiePart);
                }
            }
        }

        String setCookie = null;
        if (sb.length() > 2) {
            setCookie = sb.toString();
        }

        return new Result(setCookie, body);
    }

    private static class Result {
        final String cookie;
        final String body;

        Result(String cookie, String body) {
            this.cookie = cookie;
            this.body = body;
        }
    }
}

