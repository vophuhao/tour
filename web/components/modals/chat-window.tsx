/* eslint-disable @typescript-eslint/no-explicit-any */
/* eslint-disable @next/next/no-img-element */
'use client';
import { useEffect, useRef, useState } from 'react';
import { useAuthStore } from '@/store/auth.store';
import { useDirectMessage } from '@/hooks/useDirectMessage';
import { uploadMedia } from '@/lib/client-actions';
import { Image as ImageIcon, X, Loader2, ArrowLeft, Send } from 'lucide-react';
import { toast } from 'sonner';

interface ChatWindowProps {
    conversation: any;
    onBack: () => void;
}

export default function ChatWindow({ conversation, onBack }: ChatWindowProps) {
    const { user } = useAuthStore();
    const currentUserId = user?._id;

    const {
        messages,
        loading,
        sending,
        loadMessages,
        sendMessage: sendMsg,
        markAsRead,
        isConnected,
        socket,
    } = useDirectMessage();

    const [isOtherUserOnline, setIsOtherUserOnline] = useState(false);

    const [text, setText] = useState('');
    const listRef = useRef<HTMLDivElement | null>(null);
    const inputRef = useRef<HTMLInputElement | null>(null);
    const prevMessagesLenRef = useRef(0);
    const fileInputRef = useRef<HTMLInputElement>(null);
    
    const [selectedImages, setSelectedImages] = useState<File[]>([]);
    const [imagePreviewUrls, setImagePreviewUrls] = useState<string[]>([]);
    const [uploadingImages, setUploadingImages] = useState(false);

    const other = conversation.otherParticipant;
    const otherAvatar = other?.avatarUrl || other?.userId?.avatarUrl;
    const otherName = other?.name || other?.userId?.username || 'Người dùng';

    // Get target other user ID safely
    const otherUserId = other?.userId?._id || other?.userId || other?._id;

    useEffect(() => {
        if (!socket || !otherUserId) return;

        // Query initial online status
        socket.emit("check_online_status", otherUserId, (res: any) => {
            if (res && res.online !== undefined) {
                setIsOtherUserOnline(res.online);
            }
        });

        // Listen for status changes
        const handleStatusChange = (data: any) => {
            if (String(data.userId) === String(otherUserId)) {
                setIsOtherUserOnline(data.status === "online");
            }
        };

        socket.on("user_status_changed", handleStatusChange);
        return () => {
            socket.off("user_status_changed", handleStatusChange);
        };
    }, [socket, otherUserId]);

    useEffect(() => {
        if (!conversation?._id) return;

        (async () => {
            try {
                await loadMessages(conversation._id);
                await markAsRead(conversation._id);

                setTimeout(() => {
                    const el = listRef.current;
                    if (el) el.scrollTo({ top: el.scrollHeight, behavior: 'auto' });
                }, 100);

                setTimeout(() => inputRef.current?.focus(), 200);
            } catch (err) {
                console.error('[ChatWindow] Load messages error:', err);
            }
        })();
    }, [conversation._id, loadMessages, markAsRead]);

    useEffect(() => {
        const el = listRef.current;
        if (!el) return;

        const prev = prevMessagesLenRef.current;
        const behavior: ScrollBehavior =
            prev === 0 || messages.length > prev + 1 ? 'auto' : 'smooth';

        el.scrollTo({ top: el.scrollHeight, behavior });
        prevMessagesLenRef.current = messages.length;
    }, [messages]);

    const send = async () => {
        if (!conversation?._id) return;
        const trimmed = text.trim();
        if (!trimmed && selectedImages.length === 0) return;

        try {
            let imageUrls: string[] = [];

            // Upload images if any
            if (selectedImages.length > 0) {
                setUploadingImages(true);
                const formData = new FormData();
                selectedImages.forEach((file) => {
                    formData.append('files', file);
                });

                const uploadRes = await uploadMedia(formData);
                if (uploadRes.success && uploadRes.data) {
                    if (Array.isArray(uploadRes.data)) {
                        imageUrls = uploadRes.data as string[];
                    } else if (typeof uploadRes.data === 'string') {
                        imageUrls = [uploadRes.data];
                    } else {
                        imageUrls = [];
                    }
                } else {
                    toast.error('Không thể upload hình ảnh');
                    setUploadingImages(false);
                    return;
                }
            }

            // Send message with images as attachments
            const attachments = imageUrls.map(url => ({
                url,
                type: 'image',
            }));

            const messageContent = trimmed || '';
            const messageType = imageUrls.length > 0 && !trimmed ? 'image' : 'text';

            await sendMsg(conversation._id, {
                message: messageContent,
                messageType: messageType,
                attachments: attachments.length > 0 ? attachments : undefined,
            });

            setText('');
            setSelectedImages([]);
            setImagePreviewUrls([]);
            setUploadingImages(false);
        } catch (err) {
            console.error('[ChatWindow] Send message failed:', err);
            toast.error('Gửi tin nhắn thất bại');
            setUploadingImages(false);
        }
    };

    const handleImageSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
        const files = Array.from(e.target.files || []);
        if (files.length === 0) return;

        const newFiles = files.slice(0, 5 - selectedImages.length);
        if (newFiles.length < files.length) {
            toast.warning('Tối đa 5 hình ảnh');
        }

        setSelectedImages(prev => [...prev, ...newMocks(newFiles)]);

        const newPreviewUrls = newFiles.map(file => URL.createObjectURL(file));
        setImagePreviewUrls(prev => [...prev, ...newPreviewUrls]);

        if (e.target) {
            e.target.value = '';
        }
    };

    const newMocks = (files: File[]) => {
        return files;
    };

    const removeImage = (index: number) => {
        setSelectedImages(prev => prev.filter((_, i) => i !== index));
        URL.revokeObjectURL(imagePreviewUrls[index]);
        setImagePreviewUrls(prev => prev.filter((_, i) => i !== index));
    };

    useEffect(() => {
        return () => {
            imagePreviewUrls.forEach(url => URL.revokeObjectURL(url));
        };
    }, [imagePreviewUrls]);

    return (
        <div className="flex h-full flex-col bg-white dark:bg-slate-900">
            {/* Header */}
            <div className="flex items-center gap-3.5 border-b border-slate-100 bg-white/80 backdrop-blur-md px-5 py-4 dark:border-slate-800 dark:bg-slate-900/80">
                <button
                    onClick={onBack}
                    className="flex h-8 w-8 items-center justify-center rounded-full text-slate-500 hover:bg-slate-100 hover:text-slate-800 transition-colors dark:hover:bg-slate-800 dark:hover:text-slate-200"
                >
                    <ArrowLeft className="h-4.5 w-4.5" />
                </button>

                <div className="relative">
                    {otherAvatar ? (
                        <img src={otherAvatar} alt={otherName} className="h-10 w-10 rounded-full object-cover border border-slate-200/50 dark:border-slate-800" />
                    ) : (
                        <div className="flex h-10 w-10 items-center justify-center rounded-full bg-slate-100 text-sm font-bold text-slate-650 dark:bg-slate-800 dark:text-slate-350">
                            {otherName.charAt(0).toUpperCase()}
                        </div>
                    )}
                    <span className={`absolute bottom-0 right-0 h-2.5 w-2.5 rounded-full border-2 border-white dark:border-slate-900 ${isOtherUserOnline ? 'bg-green-500 animate-pulse' : 'bg-slate-300'}`}></span>
                </div>

                <div className="flex-1 min-w-0">
                    <p className="text-sm font-extrabold text-slate-900 dark:text-white truncate">{otherName}</p>
                    <p className="text-[10px] text-muted-foreground flex items-center gap-1.5 mt-0.5 font-medium">
                        {isOtherUserOnline ? (
                            <>
                              <span className="h-1.5 w-1.5 rounded-full bg-green-500 animate-pulse"></span>
                              Đang hoạt động
                            </>
                        ) : (
                            <>
                              <span className="h-1.5 w-1.5 rounded-full bg-slate-300"></span>
                              Ngoại tuyến
                            </>
                        )}
                    </p>
                </div>
            </div>

            {/* Messages Area */}
            <div ref={listRef} className="flex-1 space-y-4 overflow-y-auto bg-slate-50/50 p-5 dark:bg-slate-950/20 custom-scrollbar">
                {loading && messages.length === 0 && (
                    <div className="flex justify-center py-12">
                        <div className="h-5 w-5 animate-spin rounded-full border-2 border-primary border-t-transparent"></div>
                    </div>
                )}

                {!loading && messages.length === 0 && (
                    <div className="py-24 text-center">
                        <div className="text-3xl mb-2">👋</div>
                        <p className="text-xs text-muted-foreground font-semibold">Gửi lời chào để bắt đầu cuộc trò chuyện!</p>
                    </div>
                )}

                {messages.map((m: any, i: number) => {
                    const senderId = m.senderId?._id || m.senderId;
                    const isMine = String(senderId) === String(currentUserId);
                    const hasAttachments = m.attachments && m.attachments.length > 0;
                    
                    let imageUrls: string[] = [];
                    if (m.messageType === 'image' && !hasAttachments && m.message) {
                        imageUrls = m.message.split('\n').filter((url: string) => url.trim());
                    }

                    return (
                        <div
                            key={m._id || i}
                            className={`flex ${isMine ? 'justify-end' : 'justify-start'} ${m.__optimistic ? 'opacity-60' : ''}`}
                        >
                            <div className="max-w-[75%] space-y-1">
                                {m.messageType === 'image' ? (
                                    <div className="overflow-hidden rounded-2xl border border-slate-100 dark:border-slate-800">
                                        {/* Images from attachments */}
                                        {hasAttachments && (
                                            <div className={`grid gap-1 bg-slate-100 dark:bg-slate-800 ${m.attachments.length === 1 ? 'grid-cols-1' : 'grid-cols-2'}`}>
                                                {m.attachments.map((att: any, idx: number) => (
                                                    <a
                                                        key={idx}
                                                        href={att.url}
                                                        target="_blank"
                                                        rel="noopener noreferrer"
                                                        className="group/img relative block overflow-hidden"
                                                    >
                                                        <img
                                                            src={att.url}
                                                            alt={`attachment-${idx}`}
                                                            className="max-h-60 w-full object-cover transition-transform group-hover/img:scale-103"
                                                        />
                                                        <div className="absolute inset-0 bg-black/0 group-hover/img:bg-black/10 transition-colors" />
                                                    </a>
                                                ))}
                                            </div>
                                        )}

                                        {/* Images from message URLs (no attachments) */}
                                        {!hasAttachments && imageUrls.length > 0 && (
                                            <div className={`grid gap-1 bg-slate-100 dark:bg-slate-800 ${imageUrls.length === 1 ? 'grid-cols-1' : 'grid-cols-2'}`}>
                                                {imageUrls.map((url: string, idx: number) => (
                                                    <a
                                                        key={idx}
                                                        href={url}
                                                        target="_blank"
                                                        rel="noopener noreferrer"
                                                        className="group/img relative block overflow-hidden"
                                                    >
                                                        <img
                                                            src={url}
                                                            alt={`image-${idx}`}
                                                            className="max-h-60 w-full object-cover transition-transform group-hover/img:scale-103"
                                                        />
                                                        <div className="absolute inset-0 bg-black/0 group-hover/img:bg-black/10 transition-colors" />
                                                    </a>
                                                ))}
                                            </div>
                                        )}
                                    </div>
                                ) : (
                                    <div
                                        className={`px-4 py-2.5 text-xs shadow-xs leading-relaxed ${
                                            isMine
                                                ? 'bg-primary text-white rounded-2xl rounded-tr-none font-medium'
                                                : 'bg-white text-slate-800 rounded-2xl rounded-tl-none border border-slate-100 dark:bg-slate-800 dark:text-slate-200 dark:border-transparent'
                                        }`}
                                    >
                                        {/* Attachment inside text message */}
                                        {hasAttachments && (
                                            <div className={`${m.message ? 'mb-2' : ''} grid gap-1 ${m.attachments.length === 1 ? 'grid-cols-1' : 'grid-cols-2'}`}>
                                                {m.attachments.map((att: any, idx: number) => (
                                                    <a
                                                        key={idx}
                                                        href={att.url}
                                                        target="_blank"
                                                        rel="noopener noreferrer"
                                                        className="group/img relative block overflow-hidden rounded-lg"
                                                    >
                                                        <img
                                                            src={att.url}
                                                            alt={`attachment-${idx}`}
                                                            className="max-h-40 w-full object-cover transition-transform group-hover/img:scale-103"
                                                        />
                                                        <div className="absolute inset-0 bg-black/0 group-hover/img:bg-black/10 transition-colors" />
                                                    </a>
                                                ))}
                                            </div>
                                        )}

                                        {m.message && (
                                            <p className="whitespace-pre-wrap break-words">
                                                {m.message}
                                            </p>
                                        )}
                                    </div>
                                )}
                                <div className={`flex items-center gap-1 text-[10px] text-muted-foreground px-1 ${isMine ? 'justify-end' : 'justify-start'}`}>
                                    {m.createdAt &&
                                        new Date(m.createdAt).toLocaleTimeString('vi-VN', {
                                            hour: '2-digit',
                                            minute: '2-digit',
                                        })}
                                    {isMine && (
                                        m.isRead ? (
                                            <span className="text-[9px] text-primary font-bold select-none flex items-center ml-1">✓✓ Đã xem</span>
                                        ) : (
                                            <span className="text-[9px] text-slate-400 select-none flex items-center ml-1">✓ Đã gửi</span>
                                        )
                                    )}
                                </div>
                            </div>
                        </div>
                    );
                })}
            </div>

            {/* Input Section */}
            <div className="border-t border-slate-100 bg-white p-4 dark:border-slate-800 dark:bg-slate-900">
                {/* Image Previews */}
                {imagePreviewUrls.length > 0 && (
                    <div className="mb-3 flex flex-wrap gap-2.5">
                        {imagePreviewUrls.map((url, idx) => (
                            <div key={idx} className="group relative h-16 w-16 overflow-hidden rounded-xl border border-slate-200 dark:border-slate-700">
                                <img
                                    src={url}
                                    alt={`preview-${idx}`}
                                    className="h-full w-full object-cover"
                                />
                                <button
                                    onClick={() => removeImage(idx)}
                                    className="absolute inset-0 flex items-center justify-center bg-black/40 opacity-0 group-hover:opacity-100 transition-opacity text-white"
                                >
                                    <X className="h-4 w-4" />
                                </button>
                            </div>
                        ))}
                    </div>
                )}

                <div className="flex items-center gap-2">
                    {/* File Input */}
                    <input
                        ref={fileInputRef}
                        type="file"
                        accept="image/*"
                        multiple
                        onChange={handleImageSelect}
                        className="hidden"
                        disabled={uploadingImages || selectedImages.length >= 5}
                    />

                    {/* Choose Image button */}
                    <button
                        onClick={() => fileInputRef.current?.click()}
                        disabled={uploadingImages || selectedImages.length >= 5}
                        className="flex h-11 w-11 flex-shrink-0 items-center justify-center rounded-xl border border-slate-200 text-slate-500 transition-all hover:bg-slate-50 hover:text-slate-800 disabled:opacity-50 disabled:cursor-not-allowed dark:border-slate-800 dark:hover:bg-slate-850 dark:hover:text-slate-200"
                        title="Chọn hình ảnh"
                    >
                        <ImageIcon className="h-4.5 w-4.5" />
                    </button>

                    {/* Text Input */}
                    <input
                        ref={inputRef}
                        value={text}
                        onChange={(e) => setText(e.target.value)}
                        onKeyDown={(e) => {
                            if (e.key === 'Enter' && !e.shiftKey) {
                                e.preventDefault();
                                send();
                            }
                        }}
                        placeholder={isConnected ? "Nhập nội dung tin nhắn..." : "Đang kết nối..."}
                        className="flex-1 rounded-xl border border-slate-200 bg-slate-50/50 px-4 py-3 text-xs placeholder:text-slate-400 focus:border-primary focus:bg-white focus:outline-none focus:ring-1 focus:ring-primary/20 transition-all dark:border-slate-800 dark:bg-slate-950 dark:placeholder:text-slate-600 dark:focus:bg-slate-950 dark:focus:border-primary"
                        disabled={sending || uploadingImages || !isConnected}
                    />

                    {/* Send button */}
                    <button
                        onClick={send}
                        disabled={sending || uploadingImages || (!text.trim() && selectedImages.length === 0) || !isConnected}
                        className="flex h-11 w-11 flex-shrink-0 items-center justify-center rounded-xl bg-primary text-white shadow-sm shadow-primary/10 transition-all hover:bg-primary-dark hover:scale-105 active:scale-95 disabled:cursor-not-allowed disabled:opacity-50 disabled:hover:scale-100"
                    >
                        {sending || uploadingImages ? (
                            <Loader2 className="h-4 w-4 animate-spin" />
                        ) : (
                            <Send className="h-4 w-4" />
                        )}
                    </button>
                </div>
            </div>
        </div>
    );
}