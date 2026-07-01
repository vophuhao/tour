'use client';

import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar';
import { Button } from '@/components/ui/button';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Textarea } from '@/components/ui/textarea';
import { cn } from '@/lib/utils';
import { useChat } from '@ai-sdk/react';
import { Bot, Loader2, MessageCircle, Send, User, X } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import ReactMarkdown from 'react-markdown';

// Quick reply suggestions for common questions
const QUICK_REPLIES = [
  {
    id: 'find-campsite',
    label: 'Tìm địa điểm camping',
    icon: '🏕️',
    message: 'Bạn có thể giúp tôi tìm địa điểm camping phù hợp không?',
  },
  {
    id: 'booking-help',
    label: 'Hướng dẫn đặt chỗ',
    icon: '📅',
    message: 'Làm thế nào để đặt chỗ camping?',
  },
  {
    id: 'pricing',
    label: 'Giá và chính sách',
    icon: '💰',
    message: 'Cho tôi biết về giá và chính sách hủy đặt chỗ',
  },
  {
    id: 'camping-types',
    label: 'Loại hình camping',
    icon: '⛺',
    message: 'Có những loại hình camping nào?',
  },
] as const;

export function Chatbot() {
  const [isOpen, setIsOpen] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const scrollAreaRef = useRef<HTMLDivElement>(null);

  const { messages, input, handleInputChange, handleSubmit, isLoading, error } =
    useChat({
      api: '/api/chat',
      id: 'camping-chatbot', // Add stable ID to avoid Math.random() during SSR
      onError: (error: Error) => {
        console.error('Chat error:', error);
      },
    });

  // Auto-scroll to bottom when messages update or during streaming
  useEffect(() => {
    if (messagesEndRef.current) {
      messagesEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [messages, isLoading]); // Trigger on messages change AND isLoading

  // Handle keyboard shortcuts
  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      const form = e.currentTarget.form;
      if (form) {
        form.requestSubmit();
      }
    }
  };

  // Handle quick reply click
  const handleQuickReply = (message: string) => {
    // Create a synthetic change event to update input
    const syntheticEvent = {
      target: { value: message },
    } as React.ChangeEvent<HTMLInputElement>;
    handleInputChange(syntheticEvent);

    // Submit after a short delay to ensure state updates
    setTimeout(() => {
      const form = document.querySelector('form');
      if (form) {
        form.requestSubmit();
      }
    }, 10);
  };

  return (
    <>
      {/* Floating Chat Button */}
      {!isOpen && (
        <Button
          onClick={() => setIsOpen(true)}
          className="fixed right-6 bottom-24 z-50 h-14 w-14 rounded-full bg-primary shadow-lg transition-all duration-300 hover:bg-primary/90 hover:shadow-xl"
          size="icon"
        >
          <MessageCircle className="h-6 w-6 text-white" />
          <span className="sr-only">Mở chat hỗ trợ</span>
        </Button>
      )}

      {/* Chat Window */}
      {isOpen && (
        <div className="fixed right-6 bottom-6 z-50 flex h-[600px] w-[380px] flex-col rounded-2xl border border-gray-200 bg-white shadow-2xl dark:border-gray-800 dark:bg-gray-900">
          {/* Header */}
          <div className="flex items-center justify-between rounded-t-2xl border-b border-gray-200 bg-primary p-4 dark:border-gray-800">
            <div className="flex items-center gap-3">
              <div className="relative">
                <Avatar className="h-10 w-10 border-2 border-white">
                  <AvatarImage
                    src="/assets/icons/chatbot-avatar.svg"
                    alt="Bot"
                  />
                  <AvatarFallback className="bg-primary-dark text-white">
                    <Bot className="h-5 w-5" />
                  </AvatarFallback>
                </Avatar>
                <span className="absolute right-0 bottom-0 h-3 w-3 rounded-full border-2 border-white bg-green-400"></span>
              </div>
              <div>
                <h3 className="text-sm font-semibold text-white">
                  Trợ lý Campo
                </h3>
                <p className="text-xs text-white/90">Luôn sẵn sàng hỗ trợ</p>
              </div>
            </div>
            <Button
              onClick={() => setIsOpen(false)}
              variant="ghost"
              size="icon"
              className="h-8 w-8 text-white hover:bg-white/10"
            >
              <X className="h-4 w-4" />
            </Button>
          </div>

          {/* Messages Area */}
          <ScrollArea ref={scrollAreaRef} className="flex-1 p-4">
            <div className="space-y-4">
              {/* Welcome Message */}
              {messages.length === 0 && (
                <>
                  <div className="flex gap-3">
                    <Avatar className="h-8 w-8 shrink-0">
                      <AvatarImage
                        src="/assets/icons/chatbot-avatar.svg"
                        alt="Bot"
                      />
                      <AvatarFallback className="bg-primary/10 text-primary dark:bg-primary/20 dark:text-primary">
                        <Bot className="h-4 w-4" />
                      </AvatarFallback>
                    </Avatar>
                    <div className="flex-1">
                      <div className="rounded-2xl rounded-tl-none bg-gray-100 px-4 py-3 dark:bg-gray-800">
                        <p className="text-sm text-gray-700 dark:text-gray-300">
                          Chào bạn! 🏕️ Tôi là trợ lý AI. Tôi có thể giúp bạn:
                        </p>
                        <ul className="mt-2 list-inside list-disc space-y-1 text-xs text-gray-600 dark:text-gray-400">
                          <li>Tìm địa điểm camping phù hợp</li>
                          <li>Giải đáp về giá, chính sách</li>
                          <li>Hướng dẫn đặt chỗ</li>
                          <li>Gợi ý loại hình camping</li>
                        </ul>
                      </div>
                    </div>
                  </div>

                  {/* Quick Reply Buttons */}
                  <div className="ml-11 space-y-2">
                    <p className="text-xs font-medium text-gray-500 dark:text-gray-400">
                      Câu hỏi thường gặp:
                    </p>
                    <div className="grid grid-cols-1 gap-2">
                      {QUICK_REPLIES.map(reply => (
                        <Button
                          key={reply.id}
                          variant="outline"
                          size="sm"
                          onClick={() => handleQuickReply(reply.message)}
                          className="justify-start text-left text-xs hover:border-primary/30 hover:bg-primary/5 dark:hover:bg-primary/10"
                          disabled={isLoading}
                        >
                          <span className="mr-2">{reply.icon}</span>
                          {reply.label}
                        </Button>
                      ))}
                    </div>
                  </div>
                </>
              )}

              {/* Chat Messages */}
              {/* eslint-disable-next-line @typescript-eslint/no-explicit-any */}
              {messages.map((message: any) => (
                <div
                  key={message.id}
                  className={cn(
                    'flex gap-3',
                    message.role === 'user' && 'flex-row-reverse',
                  )}
                >
                  <Avatar className="h-8 w-8 shrink-0">
                    {message.role !== 'user' && (
                      <AvatarImage
                        src="/assets/icons/chatbot-avatar.svg"
                        alt="Bot"
                      />
                    )}

                    <AvatarFallback
                      className={cn(
                        message.role === 'user'
                          ? 'bg-primary text-white'
                          : 'bg-primary/10 text-primary dark:bg-primary/20 dark:text-primary',
                      )}
                    >
                      {message.role === 'user' ? (
                        <User className="h-4 w-4" />
                      ) : (
                        <Bot className="h-4 w-4" />
                      )}
                    </AvatarFallback>
                  </Avatar>

                  <div className="max-w-[80%] flex-1">
                    <div
                      className={cn(
                        'rounded-2xl px-4 py-3 text-sm',
                        message.role === 'user'
                          ? 'rounded-tr-none bg-primary text-white'
                          : 'rounded-tl-none bg-gray-100 text-gray-700 dark:bg-gray-800 dark:text-gray-300',
                      )}
                    >
                      {/* Display tool invocations */}
                      {message.toolInvocations &&
                        message.toolInvocations.length > 0 && (
                          <div className="mb-2 space-y-1">
                            {/* eslint-disable-next-line @typescript-eslint/no-explicit-any */}
                            {message.toolInvocations.map((tool: any) => (
                              <div
                                key={tool.toolCallId}
                                className="text-xs italic opacity-75"
                              >
                                {tool.state === 'call' && (
                                  <span>
                                    🔍 Đang{' '}
                                    {tool.toolName === 'searchProperties'
                                      ? 'tìm kiếm properties'
                                      : 'kiểm tra availability'}
                                    ...
                                  </span>
                                )}
                                {tool.state === 'result' && (
                                  <span>✅ Đã tìm thấy kết quả</span>
                                )}
                              </div>
                            ))}
                          </div>
                        )}

                      {/* Message content with markdown support */}
                      <div className="text-sm">
                        <ReactMarkdown
                          components={{
                            // Custom link styling - blue color, clickable, opens in new tab
                            a: ({ node, ...props }) => (
                              <a
                                {...props}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="cursor-pointer font-medium text-blue-500 underline transition-colors hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300"
                              />
                            ),
                            // Preserve other markdown elements styling
                            p: ({ node, ...props }) => (
                              <p
                                {...props}
                                className="mb-2 leading-relaxed last:mb-0"
                              />
                            ),
                            ul: ({ node, ...props }) => (
                              <ul
                                {...props}
                                className="my-2 list-inside list-disc space-y-1"
                              />
                            ),
                            ol: ({ node, ...props }) => (
                              <ol
                                {...props}
                                className="my-2 list-inside list-decimal space-y-1"
                              />
                            ),
                            li: ({ node, ...props }) => (
                              <li {...props} className="ml-2" />
                            ),
                            strong: ({ node, ...props }) => (
                              <strong {...props} className="font-semibold" />
                            ),
                            em: ({ node, ...props }) => (
                              <em {...props} className="italic" />
                            ),
                            code: ({ node, ...props }) => (
                              <code
                                {...props}
                                className="rounded bg-gray-200 px-1 py-0.5 font-mono text-xs dark:bg-gray-700"
                              />
                            ),
                          }}
                        >
                          {message.content}
                        </ReactMarkdown>
                      </div>
                    </div>

                    {/* Timestamp */}
                    <p className="mt-1 px-1 text-xs text-gray-400">
                      {message.createdAt &&
                        new Date(message.createdAt).toLocaleTimeString(
                          'vi-VN',
                          {
                            hour: '2-digit',
                            minute: '2-digit',
                          },
                        )}
                    </p>
                  </div>
                </div>
              ))}

              {/* Loading Indicator */}
              {isLoading && (
                <div className="flex gap-3">
                  <Avatar className="h-8 w-8 shrink-0">
                    <AvatarFallback className="bg-primary/10 text-primary dark:bg-primary/20 dark:text-primary">
                      <Bot className="h-4 w-4" />
                    </AvatarFallback>
                  </Avatar>
                  <div className="rounded-2xl rounded-tl-none bg-gray-100 px-4 py-3 dark:bg-gray-800">
                    <Loader2 className="h-4 w-4 animate-spin text-primary" />
                  </div>
                </div>
              )}

              {/* Error Message */}
              {error && (
                <div className="flex gap-3">
                  <Avatar className="h-8 w-8 shrink-0">
                    <AvatarFallback className="bg-red-100 text-red-600 dark:bg-red-900 dark:text-red-400">
                      <Bot className="h-4 w-4" />
                    </AvatarFallback>
                  </Avatar>
                  <div className="rounded-2xl rounded-tl-none border border-red-200 bg-red-50 px-4 py-3 dark:border-red-800 dark:bg-red-900/20">
                    <p className="text-sm text-red-600 dark:text-red-400">
                      ⚠️ Đã xảy ra lỗi. Vui lòng thử lại sau.
                    </p>
                  </div>
                </div>
              )}

              {/* Scroll anchor */}
              <div ref={messagesEndRef} />
            </div>
          </ScrollArea>

          {/* Input Area */}
          <form
            onSubmit={handleSubmit}
            className="border-t border-gray-200 p-4 dark:border-gray-800"
          >
            <div className="flex gap-2">
              <Textarea
                value={input}
                onChange={handleInputChange}
                onKeyDown={handleKeyDown}
                placeholder="Nhập câu hỏi của bạn..."
                className="max-h-[120px] min-h-11 resize-none text-sm"
                rows={1}
                disabled={isLoading}
              />
              <Button
                type="submit"
                size="icon"
                disabled={isLoading || !input.trim()}
                className="h-11 w-11 shrink-0 bg-primary hover:bg-primary-dark"
              >
                {isLoading ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <Send className="h-4 w-4" />
                )}
              </Button>
            </div>
            <p className="mt-2 text-center text-xs text-gray-500">
              Enter để gửi • Shift+Enter để xuống dòng
            </p>
          </form>
        </div>
      )}
    </>
  );
}
