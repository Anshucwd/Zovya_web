
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import javax.crypto.SecretKeyFactory;
import javax.crypto.Mac;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.time.Duration;
import java.util.Base64;
import java.util.HexFormat;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

/** Small no-Maven web server for the ZOVYA_Gifts local website. */
public class ZovyaServer {
    private static final SecureRandom RANDOM = new SecureRandom();
    private static byte[] OTP_HMAC_KEY;
    private static final Map<String, Long> SESSIONS = new ConcurrentHashMap<>();
    private static final int HASH_ITERATIONS = 210_000;
    private static Properties config;
    private static Path webRoot;

    public static void main(String[] args) throws Exception {
        config = new Properties();
        Path configPath = Paths.get("database.properties");
        if (!Files.isRegularFile(configPath)) {
            System.err.println("database.properties was not found. Create it in the project folder and start the backend again.");
            System.exit(1);
        }
        try (var in = Files.newInputStream(configPath)) { config.load(in); }
        String otpSecret = config.getProperty("otp.hmacSecret", "").trim();
        if (otpSecret.isBlank() || otpSecret.equals("CHANGE_ME")) {
            byte[] generatedSecret = new byte[32];
            RANDOM.nextBytes(generatedSecret);
            otpSecret = Base64.getEncoder().encodeToString(generatedSecret);
            Files.writeString(configPath, System.lineSeparator() + "# Generated automatically for OTP verification." +
                    System.lineSeparator() + "otp.hmacSecret=" + otpSecret + System.lineSeparator(),
                    StandardCharsets.UTF_8, java.nio.file.StandardOpenOption.APPEND);
        }
        OTP_HMAC_KEY = Base64.getDecoder().decode(otpSecret);
        if (OTP_HMAC_KEY.length < 32) throw new IllegalStateException("otp.hmacSecret must contain at least 32 bytes.");
        webRoot = Paths.get(config.getProperty("web.root", ".")).toAbsolutePath().normalize();

        Class.forName("com.mysql.cj.jdbc.Driver");
        createTables();

        int port = Integer.parseInt(config.getProperty("server.port", "8000"));
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", port), 0);
        server.createContext("/api/", ZovyaServer::handleApi);
        server.createContext("/", ZovyaServer::serveFile);
        server.setExecutor(java.util.concurrent.Executors.newCachedThreadPool());
        server.start();
        System.out.println("ZOVYA backend is running: http://localhost:" + port);
        System.out.println("Website: http://localhost:" + port + "/ZOVYA.HTML");
        System.out.println("If a password reset is requested, the demo OTP will appear in this terminal.");
    }

    private static Connection connect() throws SQLException {
        return DriverManager.getConnection(config.getProperty("db.url"),
                config.getProperty("db.username"), config.getProperty("db.password", ""));
    }

    private static void createTables() throws SQLException {
        try (Connection c = connect(); Statement s = c.createStatement()) {
            s.executeUpdate("CREATE TABLE IF NOT EXISTS user_accounts (" +
                    "id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY," +
                    "user_id VARCHAR(24) UNIQUE," +
                    "name VARCHAR(120) NOT NULL," +
                    "email VARCHAR(190) NOT NULL UNIQUE," +
                    "phone VARCHAR(32) NOT NULL UNIQUE," +
                    "password_hash VARCHAR(128) NOT NULL," +
                    "password_salt VARCHAR(64) NOT NULL," +
                    "created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP) " +
                    "ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
            s.executeUpdate("CREATE TABLE IF NOT EXISTS password_reset_codes (" +
                    "user_id BIGINT NOT NULL PRIMARY KEY," +
                    "otp_hash CHAR(64) NOT NULL," +
                    "channel VARCHAR(8) NOT NULL," +
                    "created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP," +
                    "expires_at TIMESTAMP NOT NULL," +
                    "attempts TINYINT NOT NULL DEFAULT 0," +
                    "CONSTRAINT fk_password_reset_user FOREIGN KEY (user_id) REFERENCES user_accounts(id) ON DELETE CASCADE) " +
                    "ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        }
        System.out.println("MySQL database and table are ready.");
    }

    private static void handleApi(HttpExchange x) throws IOException {
        try {
            String path = x.getRequestURI().getPath();
            String method = x.getRequestMethod();
            if (path.equals("/api/signup") && method.equals("POST")) signup(x);
            else if (path.equals("/api/login") && method.equals("POST")) login(x);
            else if (path.equals("/api/me") && method.equals("GET")) me(x);
            else if (path.equals("/api/me") && method.equals("PUT")) updateMe(x);
            else if (path.equals("/api/me/password") && method.equals("PUT")) updatePassword(x);
            else if (path.equals("/api/logout") && method.equals("POST")) logout(x);
            else if (path.equals("/api/password/forgot") && method.equals("POST")) forgot(x);
            else if (path.equals("/api/password/reset") && method.equals("POST")) resetPassword(x);
            else send(x, 404, "text/plain; charset=utf-8", "API route not found.");
        } catch (SQLException e) {
            e.printStackTrace();
            html(x, 500, "Database connection failed", "Check that MySQL is running and that database.properties has the correct connection details, then restart the backend.");
        } catch (Exception e) {
            e.printStackTrace();
            html(x, 400, "Request could not be completed", "Check the form details and try again.");
        }
    }

    private static void signup(HttpExchange x) throws Exception {
        Map<String, String> f = form(x);
        String name = required(f, "name");
        String email = required(f, "email").toLowerCase();
        String phone = required(f, "phone");
        String password = required(f, "password");
        if (password.length() < 8) { html(x, 400, "Password is too short", "Please create a password with at least 8 characters."); return; }

        byte[] salt = new byte[16]; RANDOM.nextBytes(salt);
        String salt64 = Base64.getEncoder().encodeToString(salt);
        String hash = hashPassword(password, salt);
        try (Connection c = connect(); PreparedStatement p = c.prepareStatement(
                "INSERT INTO user_accounts(name,email,phone,password_hash,password_salt) VALUES(?,?,?,?,?)",
                Statement.RETURN_GENERATED_KEYS)) {
            p.setString(1, name); p.setString(2, email); p.setString(3, phone);
            p.setString(4, hash); p.setString(5, salt64);
            p.executeUpdate();
            try (ResultSet keys = p.getGeneratedKeys()) {
                if (!keys.next()) throw new SQLException("The new account ID could not be generated.");
                long id = keys.getLong(1);
                String userId = String.format("ZOVYA%06d", id);
                try (PreparedStatement u = c.prepareStatement("UPDATE user_accounts SET user_id=? WHERE id=?")) {
                    u.setString(1, userId); u.setLong(2, id); u.executeUpdate();
                }
                html(x, 201, "Account created successfully", "Your account has been saved. Your ZOVYA User ID is: <strong>" + escape(userId) +
                        "</strong><br>Please keep this ID safe. You will need it to log in.");
            }
        } catch (SQLException e) {
            if (e.getErrorCode() == 1062) html(x, 409, "Email or phone already registered", "An account already uses this email address or phone number. Please go to the Login page.");
            else throw e;
        }
    }

    private static void login(HttpExchange x) throws Exception {
        Map<String, String> f = form(x);
        String userId = required(f, "userId");
        String password = required(f, "password");
        try (Connection c = connect(); PreparedStatement p = c.prepareStatement(
                "SELECT id,password_hash,password_salt FROM user_accounts WHERE user_id=?")) {
            p.setString(1, userId);
            try (ResultSet r = p.executeQuery()) {
                if (!r.next() || !MessageDigest.isEqual(hashPassword(password,
                        Base64.getDecoder().decode(r.getString("password_salt"))).getBytes(StandardCharsets.UTF_8),
                        r.getString("password_hash").getBytes(StandardCharsets.UTF_8))) {
                    html(x, 401, "Login failed", "The User ID or password is incorrect. Please try again."); return;
                }
                String token = UUID.randomUUID().toString();
                SESSIONS.put(token, r.getLong("id"));
                x.getResponseHeaders().add("Set-Cookie", "zovya_session=" + token + "; Path=/; HttpOnly; SameSite=Lax");
                x.getResponseHeaders().add("Location", "/ZOVYA.HTML");
                x.sendResponseHeaders(303, -1);
                x.close();
            }
        }
    }

    private static void me(HttpExchange x) throws Exception {
        Long id = sessionUser(x);
        if (id == null) { json(x, 200, "{\"authenticated\":false}"); return; }
        try (Connection c = connect(); PreparedStatement p = c.prepareStatement(
                "SELECT user_id,name,email,phone FROM user_accounts WHERE id=?")) {
            p.setLong(1, id);
            try (ResultSet r = p.executeQuery()) {
                if (!r.next()) { json(x, 200, "{\"authenticated\":false}"); return; }
                String user = "{\"id\":" + quote(r.getString("user_id")) + ",\"userId\":" + quote(r.getString("user_id")) +
                        ",\"name\":" + quote(r.getString("name")) + ",\"email\":" + quote(r.getString("email")) +
                        ",\"phone\":" + quote(r.getString("phone")) + "}";
                json(x, 200, "{\"authenticated\":true,\"user\":" + user + "}");
            }
        }
    }

    private static void updateMe(HttpExchange x) throws Exception {
        Long id = sessionUser(x);
        if (id == null) {
            json(x, 401, "{\"ok\":false,\"message\":\"Please log in before editing your account details.\"}");
            return;
        }

        Map<String, String> f = form(x);
        String name = required(f, "name");
        String email = required(f, "email").toLowerCase();
        String phone = required(f, "phone");
        if (name.length() > 120 || email.length() > 190 || phone.length() > 32 ||
                !email.matches("^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$")) {
            json(x, 400, "{\"ok\":false,\"message\":\"Enter a valid name, email address, and phone number.\"}");
            return;
        }

        try (Connection c = connect(); PreparedStatement p = c.prepareStatement(
                "UPDATE user_accounts SET name=?,email=?,phone=? WHERE id=?")) {
            p.setString(1, name);
            p.setString(2, email);
            p.setString(3, phone);
            p.setLong(4, id);
            if (p.executeUpdate() == 0) {
                json(x, 404, "{\"ok\":false,\"message\":\"The account could not be found. Please log in again.\"}");
                return;
            }
        } catch (SQLException e) {
            if (e.getErrorCode() == 1062) {
                json(x, 409, "{\"ok\":false,\"message\":\"That email address or phone number is already used by another account.\"}");
                return;
            }
            throw e;
        }

        String user = "{\"id\":" + quote(userIdFor(id)) + ",\"userId\":" + quote(userIdFor(id)) +
                ",\"name\":" + quote(name) + ",\"email\":" + quote(email) +
                ",\"phone\":" + quote(phone) + "}";
        json(x, 200, "{\"ok\":true,\"user\":" + user + "}");
    }

    private static String userIdFor(long id) throws SQLException {
        try (Connection c = connect(); PreparedStatement p = c.prepareStatement("SELECT user_id FROM user_accounts WHERE id=?")) {
            p.setLong(1, id);
            try (ResultSet r = p.executeQuery()) {
                if (r.next()) return r.getString("user_id");
            }
        }
        throw new SQLException("The current user ID could not be found.");
    }

    private static void updatePassword(HttpExchange x) throws Exception {
        Long id = sessionUser(x);
        if (id == null) {
            json(x, 401, "{\"ok\":false,\"message\":\"Please log in before changing your password.\"}");
            return;
        }

        Map<String, String> f = form(x);
        String currentPassword = required(f, "currentPassword");
        String newPassword = required(f, "newPassword");
        if (newPassword.length() < 8) {
            json(x, 400, "{\"ok\":false,\"message\":\"The new password must contain at least 8 characters.\"}");
            return;
        }

        try (Connection c = connect(); PreparedStatement p = c.prepareStatement(
                "SELECT password_hash,password_salt FROM user_accounts WHERE id=?")) {
            p.setLong(1, id);
            try (ResultSet r = p.executeQuery()) {
                if (!r.next()) {
                    json(x, 404, "{\"ok\":false,\"message\":\"The account could not be found. Please log in again.\"}");
                    return;
                }
                byte[] oldSalt = Base64.getDecoder().decode(r.getString("password_salt"));
                byte[] expectedHash = r.getString("password_hash").getBytes(StandardCharsets.UTF_8);
                byte[] actualHash = hashPassword(currentPassword, oldSalt).getBytes(StandardCharsets.UTF_8);
                if (!MessageDigest.isEqual(expectedHash, actualHash)) {
                    json(x, 401, "{\"ok\":false,\"message\":\"The current password is incorrect.\"}");
                    return;
                }
            }
        }

        byte[] newSalt = new byte[16];
        RANDOM.nextBytes(newSalt);
        String newHash = hashPassword(newPassword, newSalt);
        try (Connection c = connect(); PreparedStatement p = c.prepareStatement(
                "UPDATE user_accounts SET password_hash=?,password_salt=? WHERE id=?")) {
            p.setString(1, newHash);
            p.setString(2, Base64.getEncoder().encodeToString(newSalt));
            p.setLong(3, id);
            if (p.executeUpdate() == 0) {
                json(x, 404, "{\"ok\":false,\"message\":\"The account could not be found. Please log in again.\"}");
                return;
            }
        }
        json(x, 200, "{\"ok\":true,\"message\":\"Your password has been updated. Your User ID has not changed.\"}");
    }

    private static void logout(HttpExchange x) throws IOException {
        String token = cookie(x, "zovya_session");
        if (token != null) SESSIONS.remove(token);
        x.getResponseHeaders().add("Set-Cookie", "zovya_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax");
        json(x, 200, "{\"ok\":true}");
    }

    private static void forgot(HttpExchange x) throws Exception {
        Map<String, String> f = form(x);
        String identifier = required(f, "identifier");
        String channel = required(f, "channel").toLowerCase();
        if (!channel.equals("email") && !channel.equals("sms")) {
            json(x, 400, "{\"ok\":false,\"message\":\"Choose email or SMS for the code delivery.\"}");
            return;
        }
        if (channel.equals("email") && !emailDeliveryConfigured()) {
            json(x, 503, "{\"ok\":false,\"message\":\"Email OTP is not configured yet. Add your Gmail SMTP settings to database.properties.\"}");
            return;
        }
        if (channel.equals("sms") && !twilioDeliveryConfigured()) {
            json(x, 503, "{\"ok\":false,\"message\":\"SMS OTP is not configured yet. Add your Twilio settings to database.properties.\"}");
            return;
        }

        long userId;
        String registeredEmail;
        String registeredPhone;
        try (Connection c = connect(); PreparedStatement p = c.prepareStatement(
                "SELECT id,email,phone FROM user_accounts WHERE user_id=? OR email=? OR phone=?")) {
            p.setString(1, identifier); p.setString(2, identifier.toLowerCase()); p.setString(3, identifier);
            try (ResultSet r = p.executeQuery()) {
                if (!r.next()) {
                    json(x, 200, "{\"ok\":true,\"message\":\"If the details match an account, a code will be sent to its registered contact.\"}");
                    return;
                }
                userId = r.getLong("id");
                registeredEmail = r.getString("email");
                registeredPhone = r.getString("phone");
            }
        }

        try (Connection c = connect(); PreparedStatement p = c.prepareStatement(
                "SELECT TIMESTAMPDIFF(SECOND,created_at,CURRENT_TIMESTAMP) AS age_seconds " +
                        "FROM password_reset_codes WHERE user_id=?")) {
            p.setLong(1, userId);
            try (ResultSet r = p.executeQuery()) {
                if (r.next() && r.getInt("age_seconds") < 60) {
                    json(x, 429, "{\"ok\":false,\"message\":\"Please wait one minute before requesting another code.\"}");
                    return;
                }
            }
        }

        String otp = String.format("%06d", RANDOM.nextInt(1_000_000));
        try (Connection c = connect(); PreparedStatement delete = c.prepareStatement(
                "DELETE FROM password_reset_codes WHERE user_id=?")) {
            delete.setLong(1, userId);
            delete.executeUpdate();
            try (PreparedStatement insert = c.prepareStatement(
                    "INSERT INTO password_reset_codes(user_id,otp_hash,channel,expires_at) " +
                            "VALUES(?,?,?,DATE_ADD(CURRENT_TIMESTAMP, INTERVAL 10 MINUTE))")) {
                insert.setLong(1, userId);
                insert.setString(2, hashOtp(userId, otp));
                insert.setString(3, channel);
                insert.executeUpdate();
            }
        }

        try {
            if (channel.equals("email")) sendEmailOtp(registeredEmail, otp);
            else sendSmsOtp(registeredPhone, otp);
        } catch (Exception e) {
            deleteResetCode(userId);
            System.err.println("Could not send password reset code: " + e.getMessage());
            json(x, 502, "{\"ok\":false,\"message\":\"The code could not be sent. Check the email or Twilio settings and try again.\"}");
            return;
        }
        json(x, 200, "{\"ok\":true,\"message\":\"If the details match an account, a code has been sent to its registered contact. It expires in 10 minutes.\"}");
    }

    private static void resetPassword(HttpExchange x) throws Exception {
        Map<String, String> f = form(x);
        String identifier = required(f, "identifier");
        String otp = required(f, "otp");
        String newPassword = required(f, "newPassword");
        if (!otp.matches("\\d{6}") || newPassword.length() < 8 || newPassword.length() > 128) {
            json(x, 400, "{\"ok\":false,\"message\":\"Enter the 6-digit code and a new password of 8 to 128 characters.\"}");
            return;
        }

        try (Connection c = connect()) {
            c.setAutoCommit(false);
            long userId;
            String storedHash;
            Timestamp expiresAt;
            int attempts;
            try (PreparedStatement p = c.prepareStatement(
                    "SELECT u.id,r.otp_hash,r.expires_at,r.attempts FROM user_accounts u " +
                            "JOIN password_reset_codes r ON r.user_id=u.id " +
                            "WHERE u.user_id=? OR u.email=? OR u.phone=? FOR UPDATE")) {
                p.setString(1, identifier);
                p.setString(2, identifier.toLowerCase());
                p.setString(3, identifier);
                try (ResultSet r = p.executeQuery()) {
                    if (!r.next()) {
                        c.rollback();
                        json(x, 400, "{\"ok\":false,\"message\":\"The code is invalid or expired. Request a new code and try again.\"}");
                        return;
                    }
                    userId = r.getLong("id");
                    storedHash = r.getString("otp_hash");
                    expiresAt = r.getTimestamp("expires_at");
                    attempts = r.getInt("attempts");
                }
            }

            if (attempts >= 5 || expiresAt.before(new Timestamp(System.currentTimeMillis()))) {
                deleteResetCode(c, userId);
                c.commit();
                json(x, 400, "{\"ok\":false,\"message\":\"The code has expired. Request a new code and try again.\"}");
                return;
            }
            if (!MessageDigest.isEqual(storedHash.getBytes(StandardCharsets.US_ASCII),
                    hashOtp(userId, otp).getBytes(StandardCharsets.US_ASCII))) {
                try (PreparedStatement p = c.prepareStatement(
                        "UPDATE password_reset_codes SET attempts=attempts+1 WHERE user_id=?")) {
                    p.setLong(1, userId);
                    p.executeUpdate();
                }
                c.commit();
                json(x, 400, "{\"ok\":false,\"message\":\"The code is incorrect. Check it and try again.\"}");
                return;
            }

            byte[] salt = new byte[16];
            RANDOM.nextBytes(salt);
            try (PreparedStatement p = c.prepareStatement(
                    "UPDATE user_accounts SET password_hash=?,password_salt=? WHERE id=?")) {
                p.setString(1, hashPassword(newPassword, salt));
                p.setString(2, Base64.getEncoder().encodeToString(salt));
                p.setLong(3, userId);
                p.executeUpdate();
            }
            deleteResetCode(c, userId);
            c.commit();
            json(x, 200, "{\"ok\":true,\"message\":\"Your password has been reset. Your User ID remains the same.\"}");
        }
    }

    private static void deleteResetCode(long userId) throws SQLException {
        try (Connection c = connect()) { deleteResetCode(c, userId); }
    }

    private static void deleteResetCode(Connection c, long userId) throws SQLException {
        try (PreparedStatement p = c.prepareStatement("DELETE FROM password_reset_codes WHERE user_id=?")) {
            p.setLong(1, userId);
            p.executeUpdate();
        }
    }

    private static String hashOtp(long userId, String otp) throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(OTP_HMAC_KEY, "HmacSHA256"));
        return HexFormat.of().formatHex(mac.doFinal((userId + ":" + otp).getBytes(StandardCharsets.UTF_8)));
    }

    private static boolean emailDeliveryConfigured() {
        return !config.getProperty("smtp.username", "").isBlank() &&
                !config.getProperty("smtp.appPassword", "").isBlank();
    }

    private static boolean twilioDeliveryConfigured() {
        return !config.getProperty("twilio.accountSid", "").isBlank() &&
                !config.getProperty("twilio.authToken", "").isBlank() &&
                (!config.getProperty("twilio.from", "").isBlank() ||
                        !config.getProperty("twilio.messagingServiceSid", "").isBlank());
    }

    private static void sendEmailOtp(String recipient, String otp) throws IOException {
        String host = config.getProperty("smtp.host", "smtp.gmail.com").trim();
        int port = Integer.parseInt(config.getProperty("smtp.port", "465").trim());
        String username = config.getProperty("smtp.username", "").trim();
        String password = config.getProperty("smtp.appPassword", "").replaceAll("\\s", "");
        String from = config.getProperty("smtp.from", "").trim();
        if (from.isBlank()) from = username;
        if (!emailDeliveryConfigured() || from.isBlank()) throw new IOException("Gmail SMTP is not configured.");
        if (!recipient.matches("^[^\\s@<>]+@[^\\s@<>]+\\.[^\\s@<>]+$") ||
                !from.matches("^[^\\s@<>]+@[^\\s@<>]+\\.[^\\s@<>]+$")) {
            throw new IOException("The configured sender or registered email address is invalid.");
        }

        try (SSLSocket socket = (SSLSocket) SSLSocketFactory.getDefault().createSocket()) {
            socket.connect(new InetSocketAddress(host, port), 10_000);
            socket.setSoTimeout(15_000);
            BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.US_ASCII));
            BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.US_ASCII));
            expectSmtp(reader, 220);
            smtpCommand(writer, reader, "EHLO localhost", 250);
            smtpCommand(writer, reader, "AUTH LOGIN", 334);
            smtpCommand(writer, reader, Base64.getEncoder().encodeToString(username.getBytes(StandardCharsets.UTF_8)), 334);
            smtpCommand(writer, reader, Base64.getEncoder().encodeToString(password.getBytes(StandardCharsets.UTF_8)), 235);
            smtpCommand(writer, reader, "MAIL FROM:<" + from + ">", 250);
            smtpCommand(writer, reader, "RCPT TO:<" + recipient + ">", 250, 251);
            smtpCommand(writer, reader, "DATA", 354);

            String message = "Your ZOVYA_Gifts password reset code is " + otp + ". It expires in 10 minutes. Do not share this code.";
            String encodedMessage = Base64.getMimeEncoder(76, "\r\n".getBytes(StandardCharsets.US_ASCII))
                    .encodeToString(message.getBytes(StandardCharsets.UTF_8));
            writer.write("From: <" + from + ">\r\n");
            writer.write("To: <" + recipient + ">\r\n");
            writer.write("Subject: Your ZOVYA_Gifts password reset code\r\n");
            writer.write("MIME-Version: 1.0\r\n");
            writer.write("Content-Type: text/plain; charset=UTF-8\r\n");
            writer.write("Content-Transfer-Encoding: base64\r\n\r\n");
            writer.write(encodedMessage + "\r\n.\r\n");
            writer.flush();
            expectSmtp(reader, 250);
            smtpCommand(writer, reader, "QUIT", 221);
        }
    }

    private static void smtpCommand(BufferedWriter writer, BufferedReader reader, String command, int... expected) throws IOException {
        writer.write(command + "\r\n");
        writer.flush();
        expectSmtp(reader, expected);
    }

    private static void expectSmtp(BufferedReader reader, int... expected) throws IOException {
        String line = reader.readLine();
        if (line == null || line.length() < 3) throw new IOException("The SMTP server closed the connection.");
        int code;
        try { code = Integer.parseInt(line.substring(0, 3)); }
        catch (NumberFormatException e) { throw new IOException("The SMTP server returned an invalid response."); }
        while (line.length() > 3 && line.charAt(3) == '-') {
            line = reader.readLine();
            if (line == null) throw new IOException("The SMTP server closed the connection.");
        }
        for (int value : expected) if (code == value) return;
        throw new IOException("The SMTP server rejected the request (response " + code + ").");
    }

    private static void sendSmsOtp(String phone, String otp) throws Exception {
        String accountSid = config.getProperty("twilio.accountSid", "").trim();
        String authToken = config.getProperty("twilio.authToken", "").trim();
        String sender = config.getProperty("twilio.from", "").trim();
        String serviceSid = config.getProperty("twilio.messagingServiceSid", "").trim();
        if (!twilioDeliveryConfigured()) throw new IOException("Twilio is not configured.");

        StringBuilder body = new StringBuilder();
        body.append("To=").append(urlEncode(normalizePhone(phone)));
        if (!serviceSid.isBlank()) body.append("&MessagingServiceSid=").append(urlEncode(serviceSid));
        else body.append("&From=").append(urlEncode(sender));
        body.append("&Body=").append(urlEncode("Your ZOVYA_Gifts password reset code is " + otp + ". It expires in 10 minutes. Do not share this code."));
        String basic = Base64.getEncoder().encodeToString((accountSid + ":" + authToken).getBytes(StandardCharsets.UTF_8));
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("https://api.twilio.com/2010-04-01/Accounts/" + accountSid + "/Messages.json"))
                .timeout(Duration.ofSeconds(20))
                .header("Authorization", "Basic " + basic)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body.toString(), StandardCharsets.UTF_8))
                .build();
        HttpResponse<String> response = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build()
                .send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw new IOException("Twilio rejected the SMS request (HTTP " + response.statusCode() + ").");
        }
    }

    private static String normalizePhone(String phone) throws IOException {
        String normalized = phone.trim().replaceAll("[\\s().-]", "");
        if (normalized.matches("\\+[1-9]\\d{7,14}")) return normalized;
        if (normalized.matches("\\d{10}")) return "+91" + normalized;
        if (normalized.matches("91\\d{10}")) return "+" + normalized;
        throw new IOException("The registered phone number must use an international number format.");
    }

    private static String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private static void serveFile(HttpExchange x) throws IOException {
        if (!x.getRequestMethod().equals("GET") && !x.getRequestMethod().equals("HEAD")) { send(x, 405, "text/plain", "Method not allowed"); return; }
        String raw = x.getRequestURI().getPath();
        if (raw.equals("/")) raw = "/index.html";
        if (raw.contains("..") || raw.contains("\\")) { send(x, 400, "text/plain", "Bad path"); return; }
        Path file = webRoot.resolve(raw.substring(1)).normalize();
        if (!file.startsWith(webRoot) || !Files.isRegularFile(file) || !isWebFile(file)) { send(x, 404, "text/plain; charset=utf-8", "File not found."); return; }
        byte[] bytes = Files.readAllBytes(file);
        x.getResponseHeaders().set("Content-Type", mime(file) + "; charset=utf-8");
        x.getResponseHeaders().set("X-Content-Type-Options", "nosniff");
        if (x.getRequestMethod().equals("HEAD")) x.sendResponseHeaders(200, -1);
        else { x.sendResponseHeaders(200, bytes.length); x.getResponseBody().write(bytes); }
        x.close();
    }

    private static boolean isWebFile(Path p) {
        String n = p.getFileName().toString().toLowerCase();
        return n.endsWith(".html") || n.endsWith(".htm") || n.endsWith(".css") || n.endsWith(".js") ||
                n.endsWith(".png") || n.endsWith(".jpg") || n.endsWith(".jpeg") || n.endsWith(".webp") ||
                n.endsWith(".avif") || n.endsWith(".gif") || n.endsWith(".svg") || n.endsWith(".ico");
    }

    private static String mime(Path p) {
        String n = p.getFileName().toString().toLowerCase();
        if (n.endsWith(".html") || n.endsWith(".htm")) return "text/html";
        if (n.endsWith(".css")) return "text/css";
        if (n.endsWith(".js")) return "application/javascript";
        if (n.endsWith(".png")) return "image/png";
        if (n.endsWith(".jpg") || n.endsWith(".jpeg")) return "image/jpeg";
        if (n.endsWith(".webp")) return "image/webp";
        if (n.endsWith(".avif")) return "image/avif";
        if (n.endsWith(".gif")) return "image/gif";
        if (n.endsWith(".svg")) return "image/svg+xml";
        return "image/x-icon";
    }

    private static Map<String, String> form(HttpExchange x) throws IOException {
        String body = new String(x.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        Map<String, String> values = new HashMap<>();
        for (String pair : body.split("&")) {
            int at = pair.indexOf('=');
            String key = at < 0 ? pair : pair.substring(0, at);
            String value = at < 0 ? "" : pair.substring(at + 1);
            values.put(URLDecoder.decode(key, StandardCharsets.UTF_8), URLDecoder.decode(value, StandardCharsets.UTF_8));
        }
        return values;
    }

    private static String required(Map<String, String> f, String key) {
        String value = f.get(key);
        if (value == null || value.isBlank()) throw new IllegalArgumentException("Missing field: " + key);
        return value.trim();
    }

    private static String hashPassword(String password, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, HASH_ITERATIONS, 256);
        byte[] bytes = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
        spec.clearPassword();
        return Base64.getEncoder().encodeToString(bytes);
    }

    private static Long sessionUser(HttpExchange x) {
        String token = cookie(x, "zovya_session");
        return token == null ? null : SESSIONS.get(token);
    }

    private static String cookie(HttpExchange x, String name) {
        String header = x.getRequestHeaders().getFirst("Cookie");
        if (header == null) return null;
        for (String item : header.split(";")) {
            String[] bits = item.trim().split("=", 2);
            if (bits.length == 2 && bits[0].equals(name)) return bits[1];
        }
        return null;
    }

    private static String quote(String s) {
        return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r") + "\"";
    }

    private static String escape(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }

    private static void html(HttpExchange x, int status, String title, String message) throws IOException {
        String page = "<!doctype html><html lang='en'><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>" +
                "<title>" + escape(title) + " - ZOVYA_Gifts</title><body style='font-family:Arial,sans-serif;background:#fff0f6;padding:40px;color:#333'>" +
                "<main style='max-width:520px;margin:auto;background:white;padding:28px;border-radius:14px'><h1 style='color:#8e2875'>" + escape(title) +
                "</h1><p style='line-height:1.6'>" + message + "</p><p><a href='/Login.HTML'>Login</a> &nbsp; <a href='/ZOVYA.HTML'>Home</a></p></main></body></html>";
        send(x, status, "text/html; charset=utf-8", page);
    }

    private static void json(HttpExchange x, int status, String body) throws IOException { send(x, status, "application/json; charset=utf-8", body); }

    private static void send(HttpExchange x, int status, String type, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        x.getResponseHeaders().set("Content-Type", type);
        x.getResponseHeaders().set("Cache-Control", "no-store");
        x.sendResponseHeaders(status, bytes.length);
        x.getResponseBody().write(bytes);
        x.close();
    }
}
