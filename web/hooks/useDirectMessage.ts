/* eslint-disable @typescript-eslint/no-explicit-any */
import { sendMessageUser } from "@/lib/client-actions";
import { useAuthStore } from "@/store/auth.store";
import { useSocket } from "@/provider/socketProvider";
import { useCallback, useEffect, useRef, useState } from "react";

type DirectMessage = any;
type Conversation = { _id?: string; conversationId?: string } | null;

const API = process.env.NEXT_PUBLIC_API_URL;

function decodeUserIdFromToken(): string | null {
  try {
    if (typeof window === "undefined") return null;
    const t = localStorage.getItem("accessToken");
    if (!t) return null;
    const payload = JSON.parse(atob(t.split(".")[1]));
    return payload?.userId || payload?.user?._id || payload?.sub || null;
  } catch {
    return null;
  }
}

export function useDirectMessage() {
  const { user } = useAuthStore();
  const { socket, isConnected } = useSocket();

  const [conversation, setConversation] = useState<Conversation>(null);
  const conversationRef = useRef<Conversation>(null);
  const [messages, setMessages] = useState<DirectMessage[]>([]);
  const [loading, setLoading] = useState(false);
  const [sending, setSending] = useState(false);
  const joinedRoomRef = useRef<string | null>(null);

  useEffect(() => {
    conversationRef.current = conversation;
  }, [conversation]);

  // ✅ Join user room khi socket connected
  useEffect(() => {
    if (!socket || !isConnected) {
      console.log("[useDirectMessage] Waiting for socket connection...");
      return;
    }

    const myId = decodeUserIdFromToken();
    console.log("[useDirectMessage] Joining user room:", myId);

    if (myId) {
      socket.emit("join_user_room", String(myId), (ack: any) => {
        console.log("[useDirectMessage] join_user_room ack:", ack);
      });
    }
  }, [socket, isConnected]);

  // ✅ Listen socket events
  useEffect(() => {
    if (!socket) {
      console.log("[useDirectMessage] No socket, skipping event listeners");
      return;
    }

    const handleNewMessage = (msg: DirectMessage) => {
      console.log("[useDirectMessage] 🔔 new_message received:", msg);
      if (!msg) return;

      const msgConvId = String(msg.conversationId ?? msg.conversation?._id ?? "");
      const curConvId = String(conversationRef.current?._id ?? conversationRef.current?.conversationId ?? "");

      console.log("[useDirectMessage] Comparing convIds:", {
        msgConvId,
        curConvId,
        currentConv: conversationRef.current
      });

      if (!curConvId || msgConvId !== curConvId) {
        console.log("[useDirectMessage] ❌ Not for current conversation");
        return;
      }

      console.log("[useDirectMessage] ✅ Message is for current conversation!");

      setMessages((prev) => {
        console.log("[useDirectMessage] Current messages count:", prev.length);

        // Replace optimistic message
        const optIdx = prev.findIndex((m) => m.__optimistic && m.message === msg.message);
        if (optIdx !== -1) {
          console.log("[useDirectMessage] ✅ Replacing optimistic message at index:", optIdx);
          const copy = [...prev];
          copy.splice(optIdx, 1);
          if (!copy.some((x) => String(x._id) === String(msg._id))) {
            copy.push(msg);
          }
          console.log("[useDirectMessage] New messages count:", copy.length);
          return copy;
        }

        // Skip if already exists
        if (prev.some((m) => String(m._id) === String(msg._id))) {
          console.log("[useDirectMessage] ⚠️ Message already exists, skipping");
          return prev;
        }

        console.log("[useDirectMessage] ✅ Adding new message to list");
        const newMessages = [...prev, msg];
        console.log("[useDirectMessage] New messages count:", newMessages.length);
        return newMessages;
      });
    };

    const handleMessagesRead = (data: any) => {
      console.log("[useDirectMessage] messages_read:", data);
      if (data.conversationId === conversationRef.current?._id) {
        setMessages((prev) =>
          prev.map((m) => {
            const senderId = typeof m.senderId === 'object' && m.senderId ? m.senderId._id : m.senderId;
            const isMine = String(senderId) === String(user?._id);
            return isMine ? { ...m, isRead: true, readAt: data.readAt } : m;
          })
        );
      }
    };

    console.log('[useDirectMessage] 📡 Setting up socket listeners on:', socket.id);
    socket.on("new_message", handleNewMessage);
    socket.on("messages_read", handleMessagesRead);

    return () => {
      console.log('[useDirectMessage] 🔌 Removing socket listeners');
      socket.off("new_message", handleNewMessage);
      socket.off("messages_read", handleMessagesRead);
    };
  }, [socket, user]);

  const joinRoom = useCallback((convId: string) => {
    return new Promise<void>((resolve) => {
      if (!socket || !isConnected) {
        console.log("[useDirectMessage] ⚠️ Socket not ready, waiting...");

        const checkInterval = setInterval(() => {
          if (socket && isConnected) {
            clearInterval(checkInterval);
            performJoin();
          }
        }, 100);

        setTimeout(() => {
          clearInterval(checkInterval);
          console.log("[useDirectMessage] ⚠️ Socket wait timeout");
          resolve();
        }, 5000);
        return;
      }

      performJoin();

      function performJoin() {
        if (joinedRoomRef.current === convId) {
          console.log("[useDirectMessage] ✅ Already in room:", convId);
          return resolve();
        }

        if (joinedRoomRef.current) {
          console.log("[useDirectMessage] 🚪 Leaving previous room:", joinedRoomRef.current);
          socket?.emit("leave_conversation", joinedRoomRef.current);
        }

        console.log("[useDirectMessage] 🚪 Joining room:", convId);

        let resolved = false;
        socket?.emit("join_conversation", convId, (ack: any) => {
          joinedRoomRef.current = convId;
          resolved = true;
          console.log("[useDirectMessage] ✅ join_conversation ack:", ack);
          resolve();
        });

        setTimeout(() => {
          if (!resolved) {
            joinedRoomRef.current = convId;
            console.log("[useDirectMessage] ⚠️ join_conversation (timeout fallback)");
            resolve();
          }
        }, 1000);
      }
    });
  }, [socket, isConnected]);

  const loadMessages = useCallback(
    async (conversationId: string, page = 1, limit = 50) => {
      try {
        setLoading(true);
        console.log("[useDirectMessage] 📥 Loading messages for:", conversationId);

        const token = localStorage.getItem("accessToken");

        const res = await fetch(
          `${API}/messages/${conversationId}?page=${page}&limit=${limit}`,
          {
            credentials: "include",
            headers: {
              Authorization: `Bearer ${token}`,
            },
          }
        );

        if (!res.ok) throw new Error("Load messages failed");

        const body = await res.json();
        const msgs = body?.data ?? [];

        console.log("[useDirectMessage] ✅ Loaded", msgs.length, "messages");

        // ✅ CRITICAL: Set conversation BEFORE setting messages
        setConversation({ _id: conversationId });
        setMessages(msgs);

        await joinRoom(conversationId);

        return msgs;
      } catch (err) {
        console.error("[useDirectMessage] ❌ loadMessages error:", err);
        return [];
      } finally {
        setLoading(false);
      }
    },
    [joinRoom]
  );

  const sendMessage = useCallback(
    async (
      conversationId: string,
      payload: {
        message: string;
        messageType?: string;
        attachments?: any[];
        bookingRef?: string;
        campsiteRef?: string;
      }
    ) => {
      try {
        console.log("[useDirectMessage] 📤 Sending message:", payload.message);

        await joinRoom(conversationId);

        if (!user?._id) {
          throw new Error("User not authenticated");
        }

        const tempId = `tmp-${Date.now()}`;
        const optimistic: DirectMessage = {
          _id: tempId,
          conversationId,
          message: payload.message,
          senderId: {
            _id: user._id,
          },
          messageType: payload.messageType || "text",
          attachments: payload.attachments,
          createdAt: new Date().toISOString(),
          __optimistic: true,
        };

        console.log("[useDirectMessage] ➕ Adding optimistic message");
        setMessages((p) => [...p, optimistic]);
        setSending(true);

        const res = await sendMessageUser(conversationId, payload);

        if (!res.success) {
          console.error("[useDirectMessage] ❌ Send failed");
          setMessages((p) => p.filter((m) => m._id !== tempId));
          throw new Error(res.message || "Send failed");
        }

        console.log("[useDirectMessage] ✅ Sent successfully");
        return res.data;
      } catch (err) {
        console.error("[useDirectMessage] ❌ sendMessage error:", err);
        // Lọc bỏ tin nhắn optimistic nếu luồng gửi API bị lỗi/thất bại
        const tempId = `tmp-${Date.now()}`; // fallback
        setMessages((p) => p.filter((m) => !m._id || !String(m._id).startsWith("tmp-")));
        throw err;
      } finally {
        setSending(false);
      }
    },
    [joinRoom, user]
  );

  const markAsRead = useCallback(async (conversationId: string) => {
    try {
      const token = localStorage.getItem("accessToken");

      await fetch(`${API}/messages/${conversationId}/read`, {
        method: "PUT",
        credentials: "include",
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      console.log("[useDirectMessage] ✅ Marked as read:", conversationId);
    } catch (err) {
      console.error("[useDirectMessage] ❌ markAsRead error:", err);
    }
  }, []);

  const leaveConversation = useCallback(() => {
    if (!socket) return;

    if (joinedRoomRef.current) {
      console.log("[useDirectMessage] 🚪 Leaving conversation:", joinedRoomRef.current);
      socket.emit("leave_conversation", joinedRoomRef.current);
      joinedRoomRef.current = null;
    }

    setConversation(null);
    setMessages([]);
  }, [socket]);

  return {
    conversation,
    messages,
    loading,
    sending,
    loadMessages,
    sendMessage,
    markAsRead,
    leaveConversation,
    socket,
    isConnected,
  };
}