import { APP_ORIGIN, NODE_ENV } from "../constants/env";
import { Server as HttpServer } from "http";
import { Server, Socket } from "socket.io";
import { socketAuthMiddleware } from "./middleware/socketAuth";

let ioInstance: Server | null = null;

// Chỉ log chi tiết trong development — tránh blocking I/O ở production
const isDev = NODE_ENV === "development";
const socketLog = (msg: string) => { if (isDev) console.log(msg); };

const onlineUsers = new Set<string>();

export function initializeSocket(httpServer: HttpServer) {
  const io = new Server(httpServer, {
    cors: {
      origin: APP_ORIGIN,
      credentials: true,
      methods: ["GET", "POST"],
    },
    pingTimeout: 60000,
    pingInterval: 25000,
    path: "/socket.io",
    // Tối ưu cho tải cao: ưu tiên websocket, fallback về polling
    transports: ["websocket", "polling"],
    upgradeTimeout: 10000,
  });

  ioInstance = io;
  io.use(socketAuthMiddleware);

  // Track số lượng connections (monitoring)
  let connectionCount = 0;

  io.on("connection", (socket: Socket & { userId?: string; userRole?: string }) => {
    connectionCount++;
    const uid = socket.userId ?? "anonymous";
    socketLog(`[SOCKET] ✅ connected: socket=${socket.id} user=${uid} role=${socket.userRole || "?"} total=${connectionCount}`);

    // Track online user
    if (socket.userId) {
      onlineUsers.add(socket.userId);
      io.emit("user_status_changed", { userId: socket.userId, status: "online" });
    }

    // ✅ Join personal room
    socket.join(`user:${uid}`);
    socketLog(`[SOCKET] 🚪 user:${uid} joined personal room`);

    // ✅ CHECK ONLINE STATUS
    socket.on("check_online_status", (targetUserId: string, callback?: Function) => {
      const isOnline = onlineUsers.has(targetUserId);
      if (callback) callback({ success: true, online: isOnline });
    });

    // ✅ GET ONLINE USERS LIST
    socket.on("get_online_users", (callback?: Function) => {
      if (callback) callback(Array.from(onlineUsers));
    });

    // ✅ JOIN USER ROOM - for direct messages
    socket.on("join_user_room", (userId: string, callback?: Function) => {
      const room = `user:${userId}`;
      socket.join(room);
      socketLog(`[SOCKET] 🚪 ${uid} joined ${room}`);
      if (callback) callback({ success: true, room });
    });

    // ✅ JOIN CONVERSATION - for chat window
    socket.on("join_conversation", (conversationId: string, callback?: Function) => {
      if (!conversationId) return;
      const room = `conversation:${conversationId}`;
      socket.join(room);
      socketLog(`[SOCKET] 🚪 ${uid} joined ${room}`);
      if (callback) callback({ success: true, room });
    });

    // ✅ LEAVE CONVERSATION
    socket.on("leave_conversation", (conversationId: string) => {
      if (!conversationId) return;
      const room = `conversation:${conversationId}`;
      socket.leave(room);
      socketLog(`[SOCKET] 🚪 ${uid} left ${room}`);
    });

    // Support rooms (existing)
    socket.on("join_support_room", (conversationId: string) => {
      if (!conversationId) return;
      const room = `support:${conversationId}`;
      socket.join(room);
      socketLog(`[SOCKET] 🚪 ${uid} joined ${room}`);
    });

    socket.on("leave_support_room", (conversationId: string) => {
      if (!conversationId) return;
      const room = `support:${conversationId}`;
      socket.leave(room);
      socketLog(`[SOCKET] 🚪 ${uid} left ${room}`);
    });

    socket.on("support_send_message", (payload: any) => {
      try {
        const { conversationId, sellerId } = payload || {};
        if (!conversationId) {
          console.warn("[SOCKET] support_send_message missing conversationId", payload);
          return;
        }

        const room = `support:${conversationId}`;
        io.to(room).emit("support_new_message", payload);
        if (sellerId) {
          io.to(`user:${String(sellerId)}`).emit("support_new_message", payload);
        }

        socketLog(`[SOCKET] 📨 support_new_message emitted to ${room} (admin:${sellerId ?? "none"})`);
      } catch (err) {
        console.error("[SOCKET] ❌ error in support_send_message", err);
      }
    });

    socket.on("disconnect", (reason) => {
      connectionCount--;
      socketLog(`[SOCKET] ❌ disconnected: socket=${socket.id} user=${uid} reason=${reason} total=${connectionCount}`);

      if (socket.userId) {
        // Check if there are other sockets for the same userId
        const stillConnected = Array.from(io.sockets.sockets.values()).some(
          (s: any) => s.userId === socket.userId && s.id !== socket.id
        );
        if (!stillConnected) {
          onlineUsers.delete(socket.userId);
          io.emit("user_status_changed", { userId: socket.userId, status: "offline" });
        }
      }
    });

    socket.on("error", (err) => {
      console.error(`[SOCKET] 🚨 error: socket=${socket.id} user=${uid}`, err);
    });
  });

  return io;
}

export function getIO(): Server {
  if (!ioInstance) {
    throw new Error("Socket.IO not initialized");
  }
  return ioInstance;
}

export function notifyPropertyChange(propertyId: string) {
  try {
    const io = getIO();
    io.emit("property_data_changed", { propertyId });
    if (NODE_ENV === "development") {
      console.log(`[SOCKET] Broadcasted property_data_changed for property: ${propertyId}`);
    }
  } catch (err) {
    console.error("[SOCKET] Failed to notify property change:", err);
  }
}