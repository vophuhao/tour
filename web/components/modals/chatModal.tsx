/* eslint-disable @next/next/no-img-element */
/* eslint-disable @typescript-eslint/no-explicit-any */
'use client';
import { getUserConversations, searchUsers } from '@/lib/client-actions';
import { useSocket } from '@/provider/socketProvider';
import { useAuthStore } from '@/store/auth.store';
import { useChatModal } from '@/store/chatstore';
import { useCallback, useEffect, useState } from 'react';
import ChatWindow from './chat-window';
import { useMounted } from '@/hooks/useMounted';

const API = process.env.NEXT_PUBLIC_API_URL;

export default function ConversationsList() {
  const { user } = useAuthStore();
  const { socket } = useSocket();
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

  const formatLastMessage = (message: string) => {
    if (!message || message.trim() === '') {
      return '📷 Hình ảnh';
    }
    // Check if message contains image URLs
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

  // Handle external chat trigger from PropertyOverview
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
      if (panel && !panel.contains(e.target as Node)) {
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

        // If we have userInfo from external trigger, enrich the conversation
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
        onClick={() => setOpen(!open)}
        className="fixed right-6 bottom-6 z-50 flex h-14 w-14 items-center justify-center rounded-full bg-blue-500 text-white shadow-lg transition-all hover:bg-blue-600 hover:shadow-xl"
        aria-label="Tin nhắn"
      >
        <svg
          className="h-6 w-6"
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={2}
            d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z"
          />
        </svg>

        {totalUnread > 0 && (
          <span className="absolute -top-1 -right-1 flex h-5 w-5 items-center justify-center rounded-full bg-red-500 text-xs font-bold text-white">
            {totalUnread > 9 ? '9+' : totalUnread}
          </span>
        )}
      </button>

      {/* Panel */}
      {open && (
        <div
          id="conversations-panel"
          className="fixed right-6 bottom-24 z-[100] flex h-[600px] w-96 flex-col overflow-hidden rounded-lg bg-white shadow-2xl"
        >
          {!selectedConversation ? (
            <>
              {/* Header */}
              <div className="relative bg-white px-5 py-4 border-b border-gray-200">
                <h2 className="text-lg font-semibold text-gray-900">
                  Tin nhắn
                </h2>
                <p className="mt-0.5 text-sm text-gray-500">
                  {conversations.length} cuộc trò chuyện
                </p>
                <button
                  onClick={() => {
                    setOpen(false);
                    setSelectedConversation(null);
                    setSearchQuery('');
                    setShowSearchResults(false);
                  }}
                  className="absolute top-3 right-3 text-gray-400 hover:text-gray-600 transition-colors"
                >
                  <span className="sr-only">Đóng</span>
                  <svg
                    className="h-5 w-5"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M6 18L18 6M6 6l12 12"
                    />
                  </svg>
                </button>
              </div>

              {/* Search */}
              <div className="border-b border-gray-200 px-4 py-3">
                <div className="relative">
                  <input
                    type="text"
                    value={searchQuery}
                    onChange={e => setSearchQuery(e.target.value)}
                    placeholder="Tìm kiếm..."
                    className="w-full rounded-lg border border-gray-300 px-3 py-2 pl-9 text-sm placeholder:text-gray-400 focus:border-blue-500 focus:ring-1 focus:ring-blue-500 focus:outline-none"
                  />
                  <svg
                    className="absolute top-1/2 left-2.5 h-4 w-4 -translate-y-1/2 text-gray-400"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"
                    />
                  </svg>
                  {searching && (
                    <div className="absolute top-1/2 right-2 -translate-y-1/2">
                      <div className="h-4 w-4 animate-spin rounded-full border-2 border-blue-500 border-t-transparent"></div>
                    </div>
                  )}
                </div>
              </div>

              {/* List */}
              <div className="flex-1 overflow-y-auto">
                {showSearchResults ? (
                  <>
                    {searchResults.length === 0 && !searching && (
                      <div className="py-12 text-center text-sm text-gray-500">
                        Không tìm thấy
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
                        className="flex w-full items-center gap-3 border-b border-gray-100 px-4 py-3 text-left transition-colors hover:bg-gray-50"
                      >
                        <div className="h-11 w-11 flex-shrink-0 overflow-hidden rounded-full bg-gray-200">
                          {searchUser.avatarUrl ? (
                            <img
                              src={searchUser.avatarUrl}
                              alt={searchUser.username}
                              className="h-full w-full object-cover"
                            />
                          ) : (
                            <div className="flex h-full w-full items-center justify-center text-sm font-medium text-gray-600">
                              {searchUser.username?.charAt(0).toUpperCase()}
                            </div>
                          )}
                        </div>

                        <div className="min-w-0 flex-1">
                          <p className="truncate text-sm font-medium text-gray-900">
                            {searchUser.username || searchUser.full_name}
                          </p>
                          {searchUser.email && (
                            <p className="truncate text-xs text-gray-500">
                              {searchUser.email}
                            </p>
                          )}
                        </div>

                        <div className="rounded bg-blue-500 px-2 py-1 text-xs text-white">
                          Chat
                        </div>
                      </button>
                    ))}
                  </>
                ) : (
                  <>
                    {loading && (
                      <div className="flex justify-center py-8">
                        <div className="h-6 w-6 animate-spin rounded-full border-2 border-blue-500 border-t-transparent"></div>
                      </div>
                    )}

                    {!loading && conversations.length === 0 && (
                      <div className="py-12 text-center text-sm text-gray-500">
                        Chưa có tin nhắn
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
                            className={`flex w-full items-center gap-3 border-b border-gray-100 px-4 py-3 text-left transition-colors hover:bg-gray-50 ${hasUnread ? 'bg-blue-50' : ''
                              }`}
                          >
                            <div className="relative flex-shrink-0">
                              {avatar ? (
                                <img
                                  src={avatar}
                                  alt={name}
                                  className="h-11 w-11 rounded-full object-cover"
                                />
                              ) : (
                                <div className="flex h-11 w-11 items-center justify-center rounded-full bg-gray-200 text-sm font-medium text-gray-600">
                                  {name.charAt(0).toUpperCase()}
                                </div>
                              )}
                              {hasUnread && (
                                <span className="absolute -top-1 -right-1 flex h-5 w-5 items-center justify-center rounded-full bg-blue-500 text-xs font-medium text-white">
                                  {conv.unreadCount}
                                </span>
                              )}
                              <span className="absolute right-0 bottom-0 h-2.5 w-2.5 rounded-full border-2 border-white bg-green-500"></span>
                            </div>

                            <div className="min-w-0 flex-1">
                              <div className="flex items-center justify-between gap-2">
                                <p
                                  className={`truncate text-sm ${hasUnread ? 'font-semibold text-gray-900' : 'font-medium text-gray-700'}`}
                                >
                                  {name}
                                </p>
                                <span className="flex-shrink-0 text-xs text-gray-400">
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
                                className={`mt-0.5 truncate text-xs ${hasUnread ? 'font-medium text-gray-600' : 'text-gray-500'}`}
                              >
                                {formatLastMessage(conv.lastMessage)}
                              </p>
                            </div>
                          </button>
                        );
                      })}
                  </>
                )}
              </div>
            </>
          ) : (
            <ChatWindow
              conversation={selectedConversation}
              onBack={handleBackFromChat}
            />
          )}
        </div>
      )}
    </>
  );
}