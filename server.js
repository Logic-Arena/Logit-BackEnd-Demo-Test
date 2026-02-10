// server.js
// ============================================================
// Node.js + Express + Passport(Google/Kakao) + JWT + Socket.IO
// - 소셜 로그인 성공 시 우리 서비스 JWT(Access/Refresh) 발급
// - Socket.IO 연결 시 JWT 검증(handshake auth.token)
// - 로그인 완료 후 /auth/callback 에서 토큰 저장 → / 로 복귀
// ============================================================

require("dotenv").config();

const express = require("express");
const path = require("path");
const http = require("http");

const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const KakaoStrategy = require("passport-kakao").Strategy;

const jwt = require("jsonwebtoken");
const { Server } = require("socket.io");

// -----------------------------
// 0) 환경변수 필수값 체크(실수 방지)
// -----------------------------
const requiredEnv = [
  "JWT_ACCESS_SECRET",
  "JWT_REFRESH_SECRET",
  "FRONTEND_REDIRECT_URL",
  "GOOGLE_CLIENT_ID",
  "GOOGLE_CLIENT_SECRET",
  "GOOGLE_CALLBACK_URL",
  "KAKAO_REST_API_KEY",
  "KAKAO_CALLBACK_URL",
];
for (const key of requiredEnv) {
  if (!process.env[key]) {
    console.warn(`[WARN] Missing env: ${key}`);
  }
}

// -----------------------------
// 1) Express 기본 설정
// -----------------------------
const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true })); // (선택) form 요청도 받게
app.use(express.static(path.join(__dirname, "public"))); // 간단 프론트 서빙
app.use(passport.initialize());

// -----------------------------
// 2) (예시) DB 대신 메모리 저장
//    - 실서비스면 users/oauth_accounts 테이블로 교체
// -----------------------------
const users = new Map(); // userId -> {id, email, name, picture}
const oauthAccounts = new Map(); // "<provider>:<providerUserId>" -> userId

function randomId() {
  return Math.random().toString(36).slice(2) + Date.now().toString(36);
}

/**
 * provider 독립적으로 유저를 찾거나 생성
 * - provider: "google" | "kakao" ...
 * - providerUserId: 구글 sub / 카카오 id 등
 */
function findOrCreateUser({ provider, providerUserId, email, name, picture }) {
  const key = `${provider}:${providerUserId}`;

  let userId = oauthAccounts.get(key);
  if (!userId) {
    userId = randomId();
    users.set(userId, {
      id: userId,
      email: email ?? null,
      name: name ?? null,
      picture: picture ?? null,
    });
    oauthAccounts.set(key, userId);
  }
  return users.get(userId);
}

// -----------------------------
// 3) JWT 발급/검증 유틸
// -----------------------------
function signAccessToken(user) {
  return jwt.sign(
    { sub: user.id, email: user.email },
    process.env.JWT_ACCESS_SECRET,
    { expiresIn: process.env.ACCESS_EXPIRES_IN || "15m" },
  );
}

function signRefreshToken(user) {
  return jwt.sign(
    { sub: user.id, typ: "refresh" },
    process.env.JWT_REFRESH_SECRET,
    { expiresIn: process.env.REFRESH_EXPIRES_IN || "30d" },
  );
}

/** 보호 API용: Authorization: Bearer <accessToken> */
function authRequired(req, res, next) {
  const auth = req.headers.authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ message: "Missing token" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_ACCESS_SECRET);
    req.user = { id: decoded.sub, email: decoded.email };
    next();
  } catch {
    return res.status(401).json({ message: "Invalid/expired token" });
  }
}

// -----------------------------
// 4) Passport 전략 설정 (Google / Kakao)
// -----------------------------
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL, // http://localhost:3000/auth/google/callback
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const googleId = profile.id;
        const email = profile.emails?.[0]?.value ?? null;
        const name = profile.displayName ?? null;
        const picture = profile.photos?.[0]?.value ?? null;

        const user = findOrCreateUser({
          provider: "google",
          providerUserId: googleId,
          email,
          name,
          picture,
        });

        return done(null, user);
      } catch (e) {
        return done(e);
      }
    },
  ),
);

passport.use(
  new KakaoStrategy(
    {
      clientID: process.env.KAKAO_REST_API_KEY, // ✅ REST API 키
      // 카카오 콘솔에서 Client Secret "사용함"이면 반드시 필요
      clientSecret: process.env.KAKAO_CLIENT_SECRET || undefined,
      callbackURL: process.env.KAKAO_CALLBACK_URL, // http://localhost:3000/auth/kakao/callback
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const kakaoId = profile.id;
        const email = profile._json?.kakao_account?.email ?? null;
        const name =
          profile._json?.properties?.nickname ?? profile.displayName ?? null;
        const picture = profile._json?.properties?.profile_image ?? null;

        const user = findOrCreateUser({
          provider: "kakao",
          providerUserId: String(kakaoId),
          email,
          name,
          picture,
        });

        return done(null, user);
      } catch (e) {
        return done(e);
      }
    },
  ),
);

// -----------------------------
// 5) 소셜 로그인 라우트
// -----------------------------

// (1) Google 로그인 시작
app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] }),
);

// (2) Google 콜백 → JWT 발급 → FRONTEND_REDIRECT_URL로 이동
app.get(
  "/auth/google/callback",
  passport.authenticate("google", {
    session: false,
    failureRedirect: "/login-failed",
  }),
  (req, res) => {
    const user = req.user;

    const accessToken = signAccessToken(user);
    const refreshToken = signRefreshToken(user);

    // ✅ 로그인 결과 확인용 로그(필요 없으면 지워도 됨)
    console.log("[GOOGLE CALLBACK] user =", user);

    const redirect = new URL(process.env.FRONTEND_REDIRECT_URL);
    redirect.searchParams.set("accessToken", accessToken);
    redirect.searchParams.set("refreshToken", refreshToken);
    res.redirect(redirect.toString());
  },
);

// (3) Kakao 로그인 시작
// - 이미 카카오 로그인/동의 되어 있으면 화면 전환이 거의 없이 바로 콜백으로 돌아올 수 있음
// - 강제로 로그인 화면을 보고 싶으면 authType: "reauthenticate"를 사용
app.get(
  "/auth/kakao",
  passport.authenticate("kakao", { authType: "reauthenticate" }),
);

// (4) Kakao 콜백 → JWT 발급 → FRONTEND_REDIRECT_URL로 이동
app.get(
  "/auth/kakao/callback",
  passport.authenticate("kakao", {
    session: false,
    failureRedirect: "/login-failed",
  }),
  (req, res) => {
    const user = req.user;

    const accessToken = signAccessToken(user);
    const refreshToken = signRefreshToken(user);

    console.log("[KAKAO CALLBACK] user =", user);

    const redirect = new URL(process.env.FRONTEND_REDIRECT_URL);
    redirect.searchParams.set("accessToken", accessToken);
    redirect.searchParams.set("refreshToken", refreshToken);
    res.redirect(redirect.toString());
  },
);

app.get("/login-failed", (req, res) => {
  res.status(401).send("Social login failed");
});

// 프론트 콜백 페이지(redirect 방식 쓸 때 필요)
// - auth-callback.html: query 토큰을 localStorage 저장 후 "/"로 이동
app.get("/auth/callback", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "auth-callback.html"));
});

// (개발용) query 확인
app.get("/dev/callback", (req, res) => {
  res.send(`
    <h1>Tokens</h1>
    <pre>${JSON.stringify(req.query, null, 2)}</pre>
  `);
});

// -----------------------------
// 6) JWT 기반 보호 API 예시
// -----------------------------
app.get("/me", authRequired, (req, res) => {
  res.json({ user: users.get(req.user.id) || null });
});

// refresh token으로 access token 재발급
app.post("/auth/refresh", (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken)
    return res.status(400).json({ message: "refreshToken required" });

  try {
    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    if (decoded.typ !== "refresh")
      return res.status(401).json({ message: "Not refresh token" });

    const user = users.get(decoded.sub);
    if (!user) return res.status(401).json({ message: "User not found" });

    const newAccessToken = signAccessToken(user);
    res.json({ accessToken: newAccessToken });
  } catch {
    res.status(401).json({ message: "Invalid/expired refresh token" });
  }
});

// -----------------------------
// 7) Socket.IO (JWT 인증) 붙이기
//   - app.listen 대신 http server + io 사용
// -----------------------------
const server = http.createServer(app);

const io = new Server(server, {
  // 지금은 same-origin(localhost:3000)이라 사실상 문제 적음
  cors: { origin: true, credentials: true },
});

// 소켓 연결 전에 JWT 검증 (handshake.auth.token)
io.use((socket, next) => {
  try {
    const token = socket.handshake.auth?.token;
    if (!token) return next(new Error("NO_TOKEN"));

    const decoded = jwt.verify(token, process.env.JWT_ACCESS_SECRET);
    socket.user = { id: decoded.sub, email: decoded.email };
    next();
  } catch {
    next(new Error("BAD_TOKEN"));
  }
});

io.on("connection", (socket) => {
  console.log("✅ socket connected:", socket.id, socket.user);

  // 전체 채팅 브로드캐스트(최소 기능)
  socket.on("chat:send", (msg) => {
    const payload = {
      from: socket.user,
      text: String(msg ?? ""),
      at: new Date().toISOString(),
    };
    io.emit("chat:msg", payload);
  });

  socket.on("disconnect", (reason) => {
    console.log("❌ socket disconnected:", socket.id, reason);
  });
});

// -----------------------------
// 8) 서버 실행
// -----------------------------
server.listen(3000, () => {
  console.log("Server on http://localhost:3000");
});
