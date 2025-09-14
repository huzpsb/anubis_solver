import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

public class Main {
    private static final SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
    private static final int THREADS = 8;
    private static final int SLEEP = 1000;
    private static final ExecutorService es = Executors.newCachedThreadPool((r) -> {
        Thread t = new Thread(r);
        t.setDaemon(true);
        return t;
    });

    private static void print(String str) {
        String[] lines = str.split("\n");
        for (String line : lines) {
            System.out.println("[" + sdf.format(System.currentTimeMillis()) + "] " + line);
        }
    }

    // Performance in mind: stupid JCE looks up algorithms in a synchronized map bruh
    private static final ThreadLocal<MessageDigest> threadLocalDigest = ThreadLocal.withInitial(() -> {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    });

    private static byte[] sha256(String input) {
        try {
            MessageDigest digest = threadLocalDigest.get();
            digest.reset();
            return digest.digest(input.getBytes(StandardCharsets.UTF_8));
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private static int solvePoW(String challenge, int req) {
        final VolatileReference<Boolean> solved = new VolatileReference<>(false);
        final VolatileReference<Integer> result = new VolatileReference<>(null);
        final AtomicInteger nonce = new AtomicInteger(0);
        final CountDownLatch latch = new CountDownLatch(THREADS);
        for (int i = 0; i < THREADS; i++) {
            es.submit(() -> {
                s:
                while (true) {
                    if (solved.get()) {
                        break s;
                    }

                    int currentNonce = nonce.getAndIncrement();
                    if (currentNonce >= Integer.MAX_VALUE - THREADS) {
                        break s;
                    }

                    String attempt = challenge + currentNonce;
                    byte[] hash = sha256(attempt);

                    for (int j = 0; j < req; j++) {
                        if (hash[j] != 0) {
                            continue s;
                        }
                    }
                    solved.set(true);
                    result.set(currentNonce);
                    break s;
                }
                latch.countDown();
            });
        }
        try {
            latch.await();
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
        return result.get();
    }

    public static void main(String[] args) throws Exception {
        print("   _____              ___.   .__         _________      .__                     \n" + "  /  _  \\   ____  __ _\\_ |__ |__| ______/   _____/ ____ |  |___  __ ___________ \n" + " /  /_\\  \\ /    \\|  |  \\ __ \\|  |/  ___/\\_____  \\ /  _ \\|  |\\  \\/ // __ \\_  __ \\\n" + "/    |    \\   |  \\  |  / \\_\\ \\  |\\___ \\ /        (  <_> )  |_\\   /\\  ___/|  | \\/\n" + "\\____|__  /___|  /____/|___  /__/____  >_______  /\\____/|____/\\_/  \\___  >__|   \n" + "        \\/     \\/          \\/        \\/        \\/                      \\/       ");
        final String challengeEndpoint = "https://canine.tools/";

        print("[*] Challenge Endpoint: " + challengeEndpoint);
        print("[*] Muting SSL verification...");
        muteSSL();
        Result getChallenge = fetch(challengeEndpoint, null);

        String finalCookie = null;

        try {
            if (getChallenge.body.contains("\"algorithm\":\"metarefresh\"")) {
                int lIdx = getChallenge.body.indexOf("url=/");
                int rIdx = getChallenge.body.indexOf("\"><", lIdx);
                String middle = getChallenge.body.substring(lIdx + 5, rIdx);
                String getCookieUrl = challengeEndpoint + middle.replace("&amp;", "&");
                Thread.sleep(SLEEP);
                Result getCookie = fetch(getCookieUrl, getChallenge.cookie);
                finalCookie = getChallenge.cookie + "; " + getCookie.cookie;
                Thread.sleep(SLEEP);
            } else {
                int lIdx = getChallenge.body.indexOf("\"challenge\":\"");
                int rIdx = getChallenge.body.indexOf("\"", lIdx + 13);
                String middle = getChallenge.body.substring(lIdx + 13, rIdx);

                lIdx = getChallenge.body.indexOf("\"difficulty\":");
                rIdx = getChallenge.body.indexOf(",", lIdx + 13);
                int req = Integer.parseInt(getChallenge.body.substring(lIdx + 13, rIdx).trim());
                long now = System.currentTimeMillis();
                int ans = solvePoW(middle, req);
                print("[*] PoW solved in " + (System.currentTimeMillis() - now) + " ms, lmfao");
                byte[] hash = sha256(middle + ans);
                String hashHex = bytesToHex(hash);
                Thread.sleep(SLEEP);
                String getCookieUrl = challengeEndpoint + ".within.website/x/cmd/anubis/api/pass-challenge?response=" + hashHex + "&nonce=" + ans + "&elapsedTime=10&redir=%2F";
                Result getCookie = fetch(getCookieUrl, getChallenge.cookie);
                finalCookie = getChallenge.cookie + "; " + getCookie.cookie;
            }
        } catch (Exception ignored) {
        }

        if (finalCookie == null) {
            throw new IllegalStateException("Failed to obtain final cookie.");
        }

        Result finalResult = fetch(challengeEndpoint, finalCookie);
        print(finalResult.body);
    }

    private static void muteSSL() throws Exception {
        TrustManager[] trustAllCerts = new TrustManager[]{new X509TrustManager() {
            public X509Certificate[] getAcceptedIssuers() {
                return null;
            }

            public void checkClientTrusted(X509Certificate[] certs, String authType) {
            }

            public void checkServerTrusted(X509Certificate[] certs, String authType) {
            }
        }};

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

    private static class VolatileReference<T> {
        final Object lock = new Object();
        T value;

        T get() {
            synchronized (lock) {
                return value;
            }
        }

        void set(T value) {
            synchronized (lock) {
                this.value = value;
            }
        }

        VolatileReference(T value) {
            this.value = value;
        }
    }
}
