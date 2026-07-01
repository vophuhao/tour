/* eslint-disable @next/next/no-img-element */
/* eslint-disable @typescript-eslint/no-explicit-any */
'use client';
import { getUserConversations, searchUsers } from '@/lib/client-actions';
import { useSocket } from '@/provider/socketProvider';
import { useAuthStore } from '@/store/auth.store';
import { useChatModal } from '@/store/chatstore';
import { useCallback, useEffect, useState, useRef } from 'react';
import ChatWindow from './chat-window';
import { useMounted } from '@/hooks/useMounted';
import { motion, AnimatePresence } from 'framer-motion';
import { MessageSquare, Search, X, MessageCircle } from 'lucide-react';

const API = process.env.NEXT_PUBLIC_API_URL;

export default function ConversationsList() {
  const { user } = useAuthStore();
  const { socket, isConnected } = useSocket();
  const { isOpen: isChatModalOpen, targetUserId, targetUserInfo, closeChat } = useChatModal();

  const mounted = useMounted();

  const [open, setOpen] = useState(false);
  const [conversations, setConversations] = useState<any[]>([]);
  const [selectedConversation, setSelectedConversation] = useState<any>(null);
  const [loading, setLoading] = useState(false);

  const [searchQuery, setSearchQuery] = useState('');
  const [searchResults, setSearchResults] = useState<any[]>([]);
  const [searching, setSearching] = useState(false);
  const [showSearchResults, setShowSearchResults] = useState(false);
  const [onlineUsers, setOnlineUsers] = useState<string[]>([]);

  const formatLastMessage = (message: string) => {
    if (!message || message.trim() === '') {
      return '📷 Hình ảnh';
    }
    if (message.includes('cloudinary.com') || message.startsWith('http')) {
      return '📷 Hình ảnh';
    }
    return message || 'Bắt đầu trò chuyện...';
  };

  const loadConversations = useCallback(async () => {
    if (!user) return;

    try {
      setLoading(true);
      const res = await getUserConversations();
      setConversations(Array.isArray(res.data) ? res.data : []);
    } catch (err) {
      console.error('Load conversations error:', err);
    } finally {
      setLoading(false);
    }
  }, [user]);

  // Handle external chat trigger
  useEffect(() => {
    if (isChatModalOpen && targetUserId) {
      setOpen(true);
      startChatWithUser(targetUserId, targetUserInfo || undefined);
      closeChat();
    }
  }, [isChatModalOpen, targetUserId, targetUserInfo, closeChat]);

  useEffect(() => {
    if (!open || !user) return;
    loadConversations();
  }, [open, user, loadConversations]);

  useEffect(() => {
    if (!open || !socket) return;

    const handleConversationUpdate = (data: any) => {
      setConversations(prev => {
        const updated = prev.map(conv =>
          conv._id === data.conversationId
            ? {
              ...conv,
              lastMessage: data.lastMessage,
              lastMessageAt: data.lastMessageAt,
            }
            : conv,
        );

        return updated.sort((a, b) => {
          const aTime = new Date(a.lastMessageAt || 0).getTime();
          const bTime = new Date(b.lastMessageAt || 0).getTime();
          return bTime - aTime;
        });
      });
    };

    socket.on('conversation_updated', handleConversationUpdate);
    return () => {
      socket.off('conversation_updated', handleConversationUpdate);
    };
  }, [open, socket]);

  useEffect(() => {
    if (!open || !socket || !isConnected) return;

    // Get current online users
    socket.emit("get_online_users", (users: string[]) => {
      if (Array.isArray(users)) {
        setOnlineUsers(users.map(String));
      }
    });

    const handleStatusChange = (data: { userId: string; status: 'online' | 'offline' }) => {
      setOnlineUsers(prev => {
        const userIdStr = String(data.userId);
        if (data.status === 'online') {
          if (prev.includes(userIdStr)) return prev;
          return [...prev, userIdStr];
        } else {
          return prev.filter(uid => uid !== userIdStr);
        }
      });
    };

    socket.on("user_status_changed", handleStatusChange);
    return () => {
      socket.off("user_status_changed", handleStatusChange);
    };
  }, [open, socket, isConnected]);

  useEffect(() => {
    if (!searchQuery.trim()) {
      setSearchResults([]);
      setShowSearchResults(false);
      return;
    }

    const searchUser = async () => {
      try {
        setSearching(true);
        const res = await searchUsers(searchQuery);
        if (res.success) {
          setSearchResults(Array.isArray(res.data) ? res.data : []);
          setShowSearchResults(true);
        }
      } catch (err) {
        console.error('Search users error:', err);
      } finally {
        setSearching(false);
      }
    };

    const debounce = setTimeout(searchUser, 300);
    return () => clearTimeout(debounce);
  }, [searchQuery]);

  useEffect(() => {
    if (!open) return;

    const handleClickOutside = (e: MouseEvent) => {
      const panel = document.getElementById('conversations-panel');
      const triggerBtn = document.getElementById('conversations-trigger-btn');
      if (
        panel && 
        !panel.contains(e.target as Node) && 
        triggerBtn && 
        !triggerBtn.contains(e.target as Node)
      ) {
        setOpen(false);
        setSelectedConversation(null);
        setSearchQuery('');
        setShowSearchResults(false);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, [open]);

  const startChatWithUser = async (
    otherUserId: string,
    userInfo?: { username?: string; avatarUrl?: string; email?: string }
  ) => {
    try {
      setLoading(true);
      const token = localStorage.getItem('accessToken');
      const res = await fetch(`${API}/messages/conversations`, {
        method: 'POST',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ otherUserId }),
      });

      if (res.ok) {
        const body = await res.json();
        const conversation = body.data;

        if (userInfo && (!conversation.otherParticipant || !conversation.otherParticipant.username)) {
          conversation.otherParticipant = {
            _id: otherUserId,
            userId: {
              _id: otherUserId,
              username: userInfo.username,
              avatarUrl: userInfo.avatarUrl,
              email: userInfo.email,
            },
            name: userInfo.username,
            username: userInfo.username,
            avatarUrl: userInfo.avatarUrl,
            email: userInfo.email,
          };
        }

        setSelectedConversation(conversation);
        setSearchQuery('');
        setShowSearchResults(false);
      }
    } catch (err) {
      console.error('Start chat error:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleBackFromChat = async () => {
    setSelectedConversation(null);
    setSearchQuery('');
    setShowSearchResults(false);
    await loadConversations();
  };

  const totalUnread = conversations.reduce(
    (sum, c) => sum + (c.unreadCount || 0),
    0,
  );

  if (!mounted || !user) return null;

  return (
    <>
      {/* Floating button */}
      <button
        id="conversations-trigger-btn"
        onClick={() => setOpen(!open)}
        className="fixed right-6 bottom-6 z-50 flex h-14 w-14 items-center justify-center rounded-full bg-slate-900 text-white shadow-lg shadow-slate-950/20 transition-all hover:bg-slate-800 hover:scale-105 active:scale-95 duration-300 dark:bg-white dark:text-slate-900 dark:hover:bg-slate-100"
        aria-label="Tin nhắn"
      >
        <MessageSquare className="h-5.5 w-5.5" />
        {totalUnread > 0 && (
          <span className="absolute -top-1 -right-1 flex h-5 w-5 animate-bounce items-center justify-center rounded-full bg-red-500 text-[10px] font-extrabold text-white">
            {totalUnread > 9 ? '9+' : totalUnread}
          </span>
        )}
      </button>

      {/* Panel */}
      <AnimatePresence>
        {open && (
          <motion.div
            id="conversations-panel"
            initial={{ opacity: 0, y: 30, scale: 0.95 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 30, scale: 0.95 }}
            transition={{ duration: 0.2, ease: 'easeOut' }}
            className="fixed right-6 bottom-24 z-[100] flex h-[620px] w-[390px] flex-col overflow-hidden rounded-3xl border border-slate-200/80 bg-white/95 backdrop-blur-md shadow-2xl dark:border-slate-800/80 dark:bg-slate-900/95"
          >
            <div className="relative flex flex-1 flex-col overflow-hidden">
              <AnimatePresence mode="wait">
                {!selectedConversation ? (
                  <motion.div
                    key="list"
                    initial={{ opacity: 0, x: -15 }}
                    animate={{ opacity: 1, x: 0 }}
                    exit={{ opacity: 0, x: -15 }}
                    transition={{ duration: 0.15 }}
                    className="flex h-full flex-col"
                  >
                    {/* Header */}
                    <div className="relative bg-white/50 px-6 py-5 border-b border-slate-100 dark:border-slate-800 dark:bg-slate-900/50">
                      <h2 className="text-base font-extrabold text-slate-900 dark:text-white flex items-center gap-2">
                        <MessageSquare className="h-4 w-4 text-primary" />
                        Tin nhắn trò chuyện
                      </h2>
                      <p className="mt-0.5 text-xs text-muted-foreground">
                        {conversations.length} cuộc hội thoại
                      </p>
                      <button
                        onClick={() => {
                          setOpen(false);
                          setSelectedConversation(null);
                          setSearchQuery('');
                          setShowSearchResults(false);
                        }}
                        className="absolute top-4 right-4 flex h-7 w-7 items-center justify-center rounded-full text-slate-400 hover:bg-slate-100 hover:text-slate-600 transition-colors dark:hover:bg-slate-800 dark:hover:text-slate-200"
                      >
                        <X className="h-4 w-4" />
                      </button>
                    </div>

                    {/* Search */}
                    <div className="border-b border-slate-100 dark:border-slate-800 bg-white/30 px-5 py-3.5 dark:bg-slate-900/30">
                      <div className="relative">
                        <input
                          type="text"
                          value={searchQuery}
                          onChange={e => setSearchQuery(e.target.value)}
                          placeholder="Tìm người dùng để trò chuyện..."
                          className="w-full rounded-xl border border-slate-200 bg-white/70 px-4 py-2.5 pl-10 text-xs placeholder:text-slate-450 focus:border-primary focus:bg-white focus:outline-none focus:ring-1 focus:ring-primary/30 transition-all dark:border-slate-800 dark:bg-slate-950/70 dark:focus:bg-slate-950 dark:placeholder:text-slate-500"
                        />
                        <Search className="absolute top-1/2 left-3.5 h-3.5 w-3.5 -translate-y-1/2 text-slate-400" />
                        {searching && (
                          <div className="absolute top-1/2 right-3 -translate-y-1/2">
                            <div className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-primary border-t-transparent"></div>
                          </div>
                        )}
                      </div>
                    </div>

                    {/* List area */}
                    <div className="flex-1 overflow-y-auto custom-scrollbar">
                      {showSearchResults ? (
                        <div className="divide-y divide-slate-50 dark:divide-slate-850">
                          {searchResults.length === 0 && !searching && (
                            <div className="py-12 text-center text-xs text-muted-foreground font-semibold">
                              Không tìm thấy người dùng
                            </div>
                          )}

                          {searchResults.map(searchUser => (
                            <button
                              key={searchUser._id}
                              onClick={() => startChatWithUser(searchUser._id, {
                                username: searchUser.username,
                                avatarUrl: searchUser.avatarUrl,
                                email: searchUser.email,
                              })}
                              className="flex w-full items-center gap-3.5 px-5 py-4 text-left transition-colors hover:bg-slate-50 dark:hover:bg-slate-850/50"
                            >
                              <div className="relative flex-shrink-0">
                                <div className="h-11 w-11 overflow-hidden rounded-full border border-slate-200/50 bg-slate-100 dark:border-slate-800 dark:bg-slate-800">
                                  {searchUser.avatarUrl ? (
                                    <img
                                      src={searchUser.avatarUrl}
                                      alt={searchUser.username}
                                      className="h-full w-full object-cover"
                                    />
                                  ) : (
                                    <div className="flex h-full w-full items-center justify-center text-xs font-bold text-slate-650 dark:text-slate-350">
                                      {searchUser.username?.charAt(0).toUpperCase()}
                                    </div>
                                  )}
                                </div>
                                {/* Online indicator */}
                                {onlineUsers.includes(String(searchUser._id)) ? (
                                  <span className="absolute right-0 bottom-0 h-2.5 w-2.5 rounded-full border-2 border-white bg-green-500 dark:border-slate-900 animate-pulse"></span>
                                ) : (
                                  <span className="absolute right-0 bottom-0 h-2.5 w-2.5 rounded-full border-2 border-white bg-slate-300 dark:border-slate-900"></span>
                                )}
                              </div>

                              <div className="min-w-0 flex-1">
                                <p className="truncate text-xs font-bold text-slate-900 dark:text-white">
                                  {searchUser.username || searchUser.full_name}
                                </p>
                                {searchUser.email && (
                                  <p className="truncate text-[10px] text-muted-foreground mt-0.5">
                                    {searchUser.email}
                                  </p>
                                )}
                              </div>

                              <div className="rounded-lg bg-primary/10 px-2.5 py-1 text-[10px] font-bold text-primary hover:bg-primary/20 transition-colors">
                                Trò chuyện
                              </div>
                            </button>
                          ))}
                        </div>
                      ) : (
                        <div className="divide-y divide-slate-50 dark:divide-slate-850">
                          {loading && conversations.length === 0 && (
                            <div className="flex justify-center py-12">
                              <div className="h-5 w-5 animate-spin rounded-full border-2 border-primary border-t-transparent"></div>
                            </div>
                          )}

                          {!loading && conversations.length === 0 && (
                            <div className="py-24 text-center">
                              <MessageSquare className="mx-auto h-8 w-8 text-slate-300 dark:text-slate-700 mb-3" />
                              <p className="text-xs text-muted-foreground font-semibold">Chưa có cuộc trò chuyện nào</p>
                              <p className="text-[10px] text-muted-foreground/80 mt-1 max-w-[200px] mx-auto">Tìm kiếm người dùng ở thanh tìm kiếm để bắt đầu!</p>
                            </div>
                          )}

                          {!loading &&
                            conversations.map(conv => {
                              const other = conv.otherParticipant;
                              const avatar = other?.avatarUrl || other?.userId?.avatarUrl;
                              const name =
                                other?.username ||
                                other?.name ||
                                other?.userId?.username ||
                                'Người dùng';
                              const hasUnread = conv.unreadCount > 0;

                              return (
                                <button
                                  key={conv._id}
                                  onClick={() => setSelectedConversation(conv)}
                                  className={`flex w-full items-center gap-3.5 px-5 py-4 text-left transition-all hover:bg-slate-50 dark:hover:bg-slate-850/50 ${hasUnread ? 'bg-primary/5 dark:bg-primary/5' : ''
                                    }`}
                                >
                                  <div className="relative flex-shrink-0">
                                    {avatar ? (
                                      <img
                                        src={avatar}
                                        alt={name}
                                        className="h-11 w-11 rounded-full object-cover border border-slate-100 dark:border-slate-800"
                                      />
                                    ) : (
                                      <div className="flex h-11 w-11 items-center justify-center rounded-full bg-slate-100 text-xs font-bold text-slate-650 dark:bg-slate-800 dark:text-slate-350">
                                        {name.charAt(0).toUpperCase()}
                                      </div>
                                    )}
                                    {/* Online indicator */}
                                    {onlineUsers.includes(String(other?.userId?._id || other?.userId)) ? (
                                      <span className="absolute right-0 bottom-0 h-2.5 w-2.5 rounded-full border-2 border-white bg-green-500 dark:border-slate-900 animate-pulse"></span>
                                    ) : (
                                      <span className="absolute right-0 bottom-0 h-2.5 w-2.5 rounded-full border-2 border-white bg-slate-300 dark:border-slate-900"></span>
                                    )}
                                  </div>

                                  <div className="min-w-0 flex-1">
                                    <div className="flex items-center justify-between gap-2">
                                      <p
                                        className={`truncate text-xs ${hasUnread ? 'font-black text-slate-900 dark:text-white' : 'font-bold text-slate-700 dark:text-slate-350'}`}
                                      >
                                        {name}
                                      </p>
                                      <span className="flex-shrink-0 text-[10px] text-muted-foreground">
                                        {conv.lastMessageAt &&
                                          new Date(
                                            conv.lastMessageAt,
                                          ).toLocaleDateString('vi-VN', {
                                            day: '2-digit',
                                            month: '2-digit',
                                          })}
                                      </span>
                                    </div>
                                    <p
                                      className={`mt-1 truncate text-xs leading-normal ${hasUnread ? 'font-bold text-slate-800 dark:text-slate-200' : 'text-slate-500'}`}
                                    >
                                      {formatLastMessage(conv.lastMessage)}
                                    </p>
                                  </div>
                                </button>
                              );
                            })}
                        </div>
                      )}
                    </div>
                  </motion.div>
                ) : (
                  <motion.div
                    key="chat"
                    initial={{ opacity: 0, x: 15 }}
                    animate={{ opacity: 1, x: 0 }}
                    exit={{ opacity: 0, x: -15 }}
                    transition={{ duration: 0.15 }}
                    className="h-full"
                  >
                    <ChatWindow
                      conversation={selectedConversation}
                      onBack={handleBackFromChat}
                    />
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </>
  );
}