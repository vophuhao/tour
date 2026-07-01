/* eslint-disable @next/next/no-img-element */
/* eslint-disable @typescript-eslint/no-explicit-any */
import React, { useState, useEffect, useMemo, useRef } from 'react';
import { createPortal } from 'react-dom';
import Link from 'next/link';
import { MessageCircle, Reply, Trash2, MoreVertical, ArrowUp, ArrowDown, Search, Filter, Download, BarChart3, Image as ImageIcon, ChevronDown, ChevronUp } from 'lucide-react';
import { toast } from 'sonner';
// import { useAuth } from '../../../hooks/useAuth';
import { useCommentState } from "../../../hooks/useCommentState";
import { useCommentActions } from '../../../hooks/useCommentActions';
import { useCommentUtils } from '../../../hooks/useCommentUtils';
import { useCommentPermissions } from '../../../hooks/useCommentPermissions';
import { Comment, SortType } from '../../../types/comment';
import ReportButton from './ReportButton';
import StickerPicker from '../../../components/forum/ui/StickerPicker';

import { ConfirmDialog } from './ConfirmDialog';

type FilterType = 'all' | 'recent' | 'mostVoted' | 'withReplies';

import '../../../components/forum/style/CommentList.css';
import '../../../components/forum/style/CommentInputNew.css';
import '../../../components/forum/style/StickerPicker.css';
import { useAuthStore } from '@/store/auth.store';
import { useChatModal } from '@/store/chatstore';

// API interface để dùng chung cho forum và document
interface CommentApi {
  getCommentsByPostId: (id: string) => Promise<any>;
  createComment: (id: string, content: string, parentId?: string) => Promise<any>;
  updateComment?: (commentId: string, content: string) => Promise<any>;
  deleteComment?: (commentId: string) => Promise<any>;
  voteComment?: (commentId: string, voteType: 'upvote' | 'downvote') => Promise<any>;
}

interface CommentListProps {
  targetId: string; // postId cho forum, documentId cho document
  onCommentCountChange: (count: number) => void;
  authorId?: string; // author ID để hiển thị badge
  commentApi: CommentApi; // API instance (forumApi hoặc documentApi)
}

const CommentList: React.FC<CommentListProps> = ({ targetId, onCommentCountChange, authorId, commentApi }) => {
  // Use existing hooks
  const { user } = useAuthStore(); // Sử dụng useAuthStore thay vì useAuth để tránh lỗi context
  const { openChat } = useChatModal();
  const {
    state,
    updateState,
    sortComments,
    addComment,
    removeComment,
    addReply,
    loadAllComments
  } = useCommentState(targetId);

  const {
    actions,
    startReply,
    cancelReply,
    updateReplyContent,
    startReplyToReply,
    cancelReplyToReply,
    updateReplyToReplyContent,
    // Edit functions - disabled, only delete is available
    // startEdit,
    // cancelEdit,
    // updateEditContent,
    toggleMenu,
    closeMenu
  } = useCommentActions();

  const {
    formatTime,
    getVoteScore,
    getVoteStatus,
    getTotalCommentCount
  } = useCommentUtils();

  const {
    // canEditComment, // Edit disabled, only delete is available
    canDeleteComment
  } = useCommentPermissions();

  // Local state for search and filter
  const [searchQuery, setSearchQuery] = useState('');
  const [filterType, setFilterType] = useState<FilterType>('all');
  const [showStats, setShowStats] = useState(false);
  const [newComment, setNewComment] = useState('');
  const [isFilterBarExpanded, setIsFilterBarExpanded] = useState(false);
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [commentToDelete, setCommentToDelete] = useState<string | null>(null);

  // Sticker and image upload for main comment
  const [showStickerPicker, setShowStickerPicker] = useState(false);
  const [previewImages, setPreviewImages] = useState<string[]>([]);
  const [uploadedImages, setUploadedImages] = useState<string[]>([]);
  const stickerButtonRef = useRef<HTMLButtonElement>(null);
  const imageInputRef = useRef<HTMLInputElement>(null);
  const [stickerAnchor, setStickerAnchor] = useState<{ top: number; left: number } | null>(null);

  // Sticker and image upload for replies (stored by replyId)
  const [replyImages, setReplyImages] = useState<Record<string, string[]>>({});
  const [replyPreviewImages, setReplyPreviewImages] = useState<Record<string, string[]>>({});
  const [replyStickerPickers, setReplyStickerPickers] = useState<Record<string, boolean>>({});
  const replyStickerButtonRefs = useRef<Record<string, HTMLButtonElement | null>>({});
  const replyImageInputRefs = useRef<Record<string, HTMLInputElement | null>>({});
  const replyStickerAnchors = useRef<Record<string, { top: number; left: number } | null>>({});

  // Load comments
  const loadComments = async () => {
    updateState({ loading: true });
    try {
      const response = await commentApi.getCommentsByPostId(targetId);
      // Handle both response.data and direct response

      const data = response.data || response;
      const comments = response.data || [];

      // Process comments data
      const processedComments = comments.map((comment: any) => ({
        ...comment,
        upvotes: comment.upvotes || [],
        downvotes: comment.downvotes || [],
        childrenCount: comment.childrenCount || 0,
        replies: comment.replies || []
      }));

      updateState({ comments: processedComments });

      // Update displayed comments
      const sortedComments = sortComments(processedComments, state.sortBy);
      const initialDisplayCount = 5;
      updateState({
        displayedComments: sortedComments.slice(0, initialDisplayCount),
        hasMoreComments: sortedComments.length > initialDisplayCount,
        showAllComments: false
      });

      // Update comment count
      const totalComments = data.totalComments || 0;
      onCommentCountChange(totalComments);
    } catch (error) {
      console.error('Load comments error:', error);
      toast.error('Không thể tải bình luận. Vui lòng thử lại.');
    } finally {
      updateState({ loading: false });
    }
  };

  // Submit new comment
  // Handle image upload for main comment
  const handleImageUpload = async (files: FileList | null) => {
    if (!files || files.length === 0) return;

    try {
      const newPreviews: string[] = [];
      const filesArray = Array.from(files);

      for (const file of filesArray.slice(0, 5)) {
        if (!file.type.startsWith('image/')) {
          toast.warning(`Chỉ hỗ trợ file ảnh: ${file.name}`);
          continue;
        }
        if (file.size > 5 * 1024 * 1024) {
          toast.warning(`File ${file.name} vượt quá 5MB`);
          continue;
        }
        newPreviews.push(URL.createObjectURL(file));
      }

      setPreviewImages(prev => [...prev, ...newPreviews]);

      // Upload to Cloudinary
      // const uploaded = await chatApi.uploadFiles(filesArray.slice(0, 5).filter((f: any) => f.type.startsWith('image/')));
      // setUploadedImages(prev => [...prev, ...uploaded.map((f: any) => f.url)]);
    } catch (error) {
      toast.error('Lỗi khi upload ảnh');
    }
  };

  // Handle image upload for reply
  const handleReplyImageUpload = async (replyId: string, files: FileList | null) => {
    if (!files || files.length === 0) return;

    try {
      const newPreviews: string[] = [];
      const filesArray = Array.from(files);

      for (const file of filesArray.slice(0, 5)) {
        if (!file.type.startsWith('image/')) {
          toast.warning(`Chỉ hỗ trợ file ảnh: ${file.name}`);
          continue;
        }
        if (file.size > 5 * 1024 * 1024) {
          toast.warning(`File ${file.name} vượt quá 5MB`);
          continue;
        }
        newPreviews.push(URL.createObjectURL(file));
      }

      setReplyPreviewImages(prev => ({
        ...prev,
        [replyId]: [...(prev[replyId] || []), ...newPreviews]
      }));

      // const uploaded = await chatApi.uploadFiles(filesArray.slice(0, 5).filter((f: any) => f.type.startsWith('image/')));
      // setReplyImages(prev => ({
      //   ...prev,
      //   [replyId]: [...(prev[replyId] || []), ...uploaded.map((f: any) => f.url)]
      // }));
    } catch (error) {
      toast.error('Lỗi khi upload ảnh');
    }
  };

  // Handle sticker select for main comment
  const handleStickerSelect = (gifUrl: string) => {
    setUploadedImages(prev => [...prev, gifUrl]);
    setShowStickerPicker(false);
  };

  // Handle sticker select for reply
  const handleReplyStickerSelect = (replyId: string, gifUrl: string) => {
    setReplyImages(prev => ({
      ...prev,
      [replyId]: [...(prev[replyId] || []), gifUrl]
    }));
    setReplyStickerPickers(prev => ({ ...prev, [replyId]: false }));
  };

  // Toggle sticker picker for main comment
  const handleStickerToggle = () => {
    const btn = stickerButtonRef.current;
    if (btn) {
      const rect = btn.getBoundingClientRect();
      setStickerAnchor({ top: rect.top, left: rect.left });
    }
    setShowStickerPicker(prev => !prev);
  };

  // Toggle sticker picker for reply
  const handleReplyStickerToggle = (replyId: string) => {
    const btn = replyStickerButtonRefs.current[replyId];
    if (btn) {
      const rect = btn.getBoundingClientRect();
      replyStickerAnchors.current[replyId] = { top: rect.top, left: rect.left };
    }
    setReplyStickerPickers(prev => ({ ...prev, [replyId]: !prev[replyId] }));
  };

  const handleSubmitComment = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!newComment.trim() && uploadedImages.length === 0 || state.submitting) return;
    if (!user) {
      toast.warning('Vui lòng đăng nhập để bình luận');
      return;
    }

    updateState({ submitting: true });
    try {
      // Combine text and images
      let content = newComment.trim();
      if (uploadedImages.length > 0) {
        const imageTags = uploadedImages.map(url => `<img src="${url}" alt="image" style="max-width: 100%; border-radius: 8px; margin: 8px 0;" />`).join('');
        content = content ? `${content}\n${imageTags}` : imageTags;
      }

      const response = await commentApi.createComment(targetId, content);

      // Handle both response.data and direct response
      const data = response.data || response;
      const comment = data.comment || data.data || data;

      const newCommentData = {
        ...comment,
        upvotes: [],
        downvotes: [],
        childrenCount: 0
      };

      addComment(newCommentData);
      setNewComment('');
      setPreviewImages([]);
      setUploadedImages([]);

      const newCommentsList = [newCommentData, ...state.comments];
      onCommentCountChange(getTotalCommentCount(newCommentsList));
      toast.success('Đã gửi bình luận thành công!');
    } catch (error: any) {
      if (error.response?.status === 401) {
        toast.warning('Vui lòng đăng nhập để bình luận');
      } else if (error.response?.status === 429) {
        toast.warning('Bạn đã gửi quá nhiều bình luận. Vui lòng thử lại sau.');
      } else {
        toast.error('Có lỗi xảy ra khi gửi bình luận');
      }
    } finally {
      updateState({ submitting: false });
    }
  };

  // Submit reply
  const handleSubmitReply = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!actions.replyContent.trim() && !replyImages[actions.replyingTo || '']?.length || !actions.replyingTo || state.submitting) return;
    if (!user) {
      toast.warning('Vui lòng đăng nhập để trả lời');
      return;
    }

    updateState({ submitting: true });
    try {
      // Combine text and images for reply
      let content = actions.replyContent.trim();
      const replyImageUrls = replyImages[actions.replyingTo] || [];
      if (replyImageUrls.length > 0) {
        const imageTags = replyImageUrls.map(url => `<img src="${url}" alt="image" style="max-width: 100%; border-radius: 8px; margin: 8px 0;" />`).join('');
        content = content ? `${content}\n${imageTags}` : imageTags;
      }

      const response = await commentApi.createComment(targetId, content, actions.replyingTo);

      // Handle both response.data and direct response
      const data = response.data || response;
      const comment = data.comment || data.data || data;

      const newReplyData = {
        ...comment,
        upvotes: [],
        downvotes: [],
        childrenCount: 0
      };

      addReply(actions.replyingTo, newReplyData);

      // Clean up reply images
      const replyingToId = actions.replyingTo;
      setReplyImages(prev => {
        const newState = { ...prev };
        delete newState[replyingToId];
        return newState;
      });
      setReplyPreviewImages(prev => {
        const newState = { ...prev };
        if (newState[replyingToId]) {
          newState[replyingToId].forEach(url => URL.revokeObjectURL(url));
          delete newState[replyingToId];
        }
        return newState;
      });

      cancelReply();
      const updatedComments = state.comments.map((c: any) => {
        if (c._id === actions.replyingTo) {
          return {
            ...c,
            childrenCount: (c.childrenCount || 0) + 1,
            replies: [...(c.replies || []), newReplyData],
          };
        }
        return c;
      });
      onCommentCountChange(getTotalCommentCount(updatedComments));
      toast.success('Đã gửi trả lời thành công!');
    } catch (error: any) {
      if (error.response?.status === 401) {
        toast.warning('Vui lòng đăng nhập để trả lời');
      } else if (error.response?.status === 429) {
        toast.warning('Bạn đã gửi quá nhiều trả lời. Vui lòng thử lại sau.');
      } else {
        toast.error('Có lỗi xảy ra khi gửi trả lời');
      }
    } finally {
      updateState({ submitting: false });
    }
  };

  // Submit reply to reply
  const handleSubmitReplyToReply = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!actions.replyToReplyContent.trim() || !actions.replyToReply || state.submitting) return;
    if (!user) {
      toast.warning('Vui lòng đăng nhập để trả lời');
      return;
    }

    updateState({ submitting: true });
    try {
      const response = await commentApi.createComment(targetId, actions.replyToReplyContent.trim(), actions.replyToReply);

      // Handle both response.data and direct response
      const data = response.data || response;
      const comment = data.comment || data.data || data;

      const newReplyData = {
        ...comment,
        upvotes: [],
        downvotes: [],
        childrenCount: 0
      };

      // Find and update the parent comment/reply
      const updatedComments = state.comments.map((comment: any) => {
        if (comment._id === actions.replyToReply) {
          return {
            ...comment,
            childrenCount: (comment.childrenCount || 0) + 1,
            replies: [...(comment.replies || []), newReplyData]
          };
        }

        if (comment.replies && comment.replies.length > 0) {
          const updatedReplies = comment.replies.map((reply: any) => {
            if (reply._id === actions.replyToReply) {
              return {
                ...reply,
                childrenCount: (reply.childrenCount || 0) + 1,
                replies: [...(reply.replies || []), newReplyData]
              };
            }
            return reply;
          });

          return {
            ...comment,
            replies: updatedReplies
          };
        }

        return comment;
      });

      updateState({ comments: updatedComments });

      // Update displayed comments
      const sortedUpdatedComments = sortComments(updatedComments, state.sortBy);
      const initialDisplayCount = 5;
      updateState({
        displayedComments: sortedUpdatedComments.slice(0, initialDisplayCount),
        hasMoreComments: sortedUpdatedComments.length > initialDisplayCount,
        showAllComments: false
      });

      cancelReplyToReply();
      onCommentCountChange(getTotalCommentCount(updatedComments));
      toast.success('Đã gửi trả lời thành công!');
    } catch (error: any) {
      if (error.response?.status === 401) {
        toast.warning('Vui lòng đăng nhập để trả lời');
      } else if (error.response?.status === 429) {
        toast.warning('Bạn đã gửi quá nhiều trả lời. Vui lòng thử lại sau.');
      } else {
        toast.error('Có lỗi xảy ra khi gửi trả lời');
      }
    } finally {
      updateState({ submitting: false });
    }
  };

  // Vote comment
  const handleVote = async (commentId: string, voteType: 'upvote' | 'downvote') => {
    if (!user) {
      toast.warning('Vui lòng đăng nhập để vote');
      return;
    }

    // Optimistic update
    const updatedComments = state.comments.map((comment: any) => {
      if (comment._id === commentId) {
        const upvotes = comment.upvotes || [];
        const downvotes = comment.downvotes || [];

        let newUpvotes = [...upvotes];
        let newDownvotes = [...downvotes];

        if (voteType === 'upvote') {
          if (upvotes.includes(user._id)) {
            newUpvotes = upvotes.filter((id: string) => id !== user._id);
          } else {
            newUpvotes = [...upvotes, user._id];
            newDownvotes = downvotes.filter((id: string) => id !== user._id);
          }
        } else {
          if (downvotes.includes(user._id)) {
            newDownvotes = downvotes.filter((id: string) => id !== user._id);
          } else {
            newDownvotes = [...downvotes, user._id];
            newUpvotes = upvotes.filter((id: string) => id !== user._id);
          }
        }

        return {
          ...comment,
          upvotes: newUpvotes,
          downvotes: newDownvotes
        };
      }

      // Kiểm tra replies (cấp 1)
      if (comment.replies && comment.replies.length > 0) {
        const updatedReplies = comment.replies.map((reply: any) => {
          if (reply._id === commentId) {
            const upvotes = reply.upvotes || [];
            const downvotes = reply.downvotes || [];

            let newUpvotes = [...upvotes];
            let newDownvotes = [...downvotes];

            if (voteType === 'upvote') {
              if (upvotes.includes(user._id)) {
                newUpvotes = upvotes.filter((id: string) => id !== user._id);
              } else {
                newUpvotes = [...upvotes, user._id];
                newDownvotes = downvotes.filter((id: string) => id !== user._id);
              }
            } else {
              if (downvotes.includes(user._id)) {
                newDownvotes = downvotes.filter((id: string) => id !== user._id);
              } else {
                newDownvotes = [...downvotes, user._id];
                newUpvotes = upvotes.filter((id: string) => id !== user._id);
              }
            }

            return {
              ...reply,
              upvotes: newUpvotes,
              downvotes: newDownvotes
            };
          }
          return reply;
        });

        return {
          ...comment,
          replies: updatedReplies
        };
      }

      return comment;
    });

    const sortedUpdatedComments = sortComments(updatedComments, state.sortBy);

    updateState({ comments: updatedComments });

    // Update displayed comments
    const initialDisplayCount = 5;
    updateState({
      displayedComments: sortedUpdatedComments.slice(0, initialDisplayCount),
      hasMoreComments: sortedUpdatedComments.length > initialDisplayCount,
      showAllComments: false
    });

    try {
      if (commentApi.voteComment) {
        await commentApi.voteComment(commentId, voteType);
      }
    } catch (error: any) {
      toast.error('Có lỗi xảy ra khi vote. Vui lòng thử lại.');

      // Revert optimistic update
      const revertedComments = state.comments.map((comment: any) => {
        if (comment._id === commentId) {
          const upvotes = comment.upvotes || [];
          const downvotes = comment.downvotes || [];

          let newUpvotes = [...upvotes];
          let newDownvotes = [...downvotes];

          if (voteType === 'upvote') {
            if (upvotes.includes(user._id)) {
              newUpvotes = upvotes.filter((id: string) => id !== user._id);
            } else {
              newUpvotes = [...upvotes, user._id];
              newDownvotes = downvotes.filter((id: string) => id !== user._id);
            }
          } else {
            if (downvotes.includes(user._id)) {
              newDownvotes = downvotes.filter((id: string) => id !== user._id);
            } else {
              newDownvotes = [...downvotes, user._id];
              newUpvotes = upvotes.filter((id: string) => id !== user._id);
            }
          }

          return {
            ...comment,
            upvotes: newUpvotes,
            downvotes: newDownvotes
          };
        }

        // Kiểm tra replies (cấp 1)
        if (comment.replies && comment.replies.length > 0) {
          const updatedReplies = comment.replies.map((reply: any) => {
            if (reply._id === commentId) {
              const upvotes = reply.upvotes || [];
              const downvotes = reply.downvotes || [];

              let newUpvotes = [...upvotes];
              let newDownvotes = [...downvotes];

              if (voteType === 'upvote') {
                if (upvotes.includes(user._id)) {
                  newUpvotes = upvotes.filter((id: string) => id !== user._id);
                } else {
                  newUpvotes = [...upvotes, user._id];
                  newDownvotes = downvotes.filter((id: string) => id !== user._id);
                }
              } else {
                if (downvotes.includes(user._id)) {
                  newDownvotes = downvotes.filter((id: string) => id !== user._id);
                } else {
                  newDownvotes = [...downvotes, user._id];
                  newUpvotes = upvotes.filter((id: string) => id !== user._id);
                }
              }

              return {
                ...reply,
                upvotes: newUpvotes,
                downvotes: newDownvotes
              };
            }
            return reply;
          });

          return {
            ...comment,
            replies: updatedReplies
          };
        }

        return comment;
      });

      updateState({ comments: revertedComments });

      // Update displayed comments
      const sortedRevertedComments = sortComments(revertedComments, state.sortBy);
      const initialDisplayCount = 5;
      updateState({
        displayedComments: sortedRevertedComments.slice(0, initialDisplayCount),
        hasMoreComments: sortedRevertedComments.length > initialDisplayCount,
        showAllComments: false
      });
    }
  };

  // Edit comment - disabled, only delete is available
  // Uncomment this function if edit feature is needed in the future
  /*
  const handleEditComment = async (commentId: string) => {
    if (!actions.editContent.trim() || state.submitting) return;

    updateState({ submitting: true });
    try {
      if (commentApi.updateComment) {
        await commentApi.updateComment(commentId, actions.editContent.trim());
      }
      
      const updatedComments = state.comments.map(comment => {
        if (comment._id === commentId) {
          return { ...comment, content: actions.editContent.trim() };
        }
        
        if (comment.replies && comment.replies.length > 0) {
          const updatedReplies = comment.replies.map(reply => {
            if (reply._id === commentId) {
              return { ...reply, content: actions.editContent.trim() };
            }
            return reply;
          });
          
          return {
            ...comment,
            replies: updatedReplies
          };
        }
        
        return comment;
      });
      
      updateState({ comments: updatedComments });
      
      // Update displayed comments
      const sortedUpdatedComments = sortComments(updatedComments, state.sortBy);
      const initialDisplayCount = 5;
      updateState({
        displayedComments: sortedUpdatedComments.slice(0, initialDisplayCount),
        hasMoreComments: sortedUpdatedComments.length > initialDisplayCount,
        showAllComments: false
      });
      
      cancelEdit();
      toast.success('Đã cập nhật bình luận thành công!');
    } catch (error: any) {
      toast.error('Có lỗi xảy ra khi cập nhật bình luận');
    } finally {
      updateState({ submitting: false });
    }
  };
  */

  // Delete comment
  const handleDeleteComment = (commentId: string) => {
    setCommentToDelete(commentId);
    setShowDeleteConfirm(true);
  };

  const confirmDeleteComment = async () => {
    if (!commentToDelete) return;

    try {
      if (commentApi.deleteComment) {
        await commentApi.deleteComment(commentToDelete);
      }
      removeComment(commentToDelete);
      toast.success('Đã xóa bình luận thành công!');
      setShowDeleteConfirm(false);
      setCommentToDelete(null);
    } catch (error: any) {
      toast.error('Có lỗi xảy ra khi xóa bình luận');
    }
  };

  // Load more comments
  const handleLoadMoreComments = () => {
    loadAllComments();
  };

  // Handle sort change
  const handleSortChange = (newSortBy: SortType) => {
    updateState({ sortBy: newSortBy });

    // Update displayed comments
    const sortedComments = sortComments(state.comments, newSortBy);
    const initialDisplayCount = 5;
    updateState({
      displayedComments: sortedComments.slice(0, initialDisplayCount),
      hasMoreComments: sortedComments.length > initialDisplayCount,
      showAllComments: false
    });
  };

  // Handle expand replies
  const handleExpandReplies = (commentId: string) => {
    const newExpanded = new Set(state.expandedReplies);
    newExpanded.add(commentId);
    updateState({ expandedReplies: newExpanded });
  };

  // Handle collapse replies
  const handleCollapseReplies = (commentId: string) => {
    const newExpanded = new Set(state.expandedReplies);
    newExpanded.delete(commentId);
    updateState({ expandedReplies: newExpanded });
  };

  // Filter and search logic
  const filteredAndSearchedComments = useMemo(() => {
    let result = state.comments;

    if (searchQuery.trim()) {
      const searchTerm = searchQuery.toLowerCase();
      result = result.filter((comment: any) => {
        const matchesContent = comment.content.toLowerCase().includes(searchTerm);
        const matchesAuthor = comment.userId?.username ? comment.userId.username.toLowerCase().includes(searchTerm) : false;
        const matchesReplies = comment.replies?.some((reply: any) =>
          reply.content.toLowerCase().includes(searchTerm) ||
          (reply.userId?.username ? reply.userId.username.toLowerCase().includes(searchTerm) : false)
        ) || false;

        return matchesContent || matchesAuthor || matchesReplies;
      });
    }

    switch (filterType) {
      case 'recent':
        const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
        result = result.filter((comment: any) => new Date(comment.createdAt) > oneDayAgo);
        break;
      case 'mostVoted':
        result = result.filter((comment: any) => getVoteScore(comment) > 5);
        break;
      case 'withReplies':
        result = result.filter((comment: any) => comment.replies && comment.replies.length > 0);
        break;
      default:
        break;
    }

    return result;
  }, [state.comments, searchQuery, filterType]);

  const sortedFilteredComments = useMemo(() => {
    return sortComments(filteredAndSearchedComments, state.sortBy);
  }, [filteredAndSearchedComments, state.sortBy, sortComments]);

  // Update displayed comments when filtered/sorted comments change
  useEffect(() => {
    if (!state.showAllComments) {
      const initialDisplayCount = 5;
      const displayed = sortedFilteredComments.slice(0, initialDisplayCount);
      updateState({
        displayedComments: displayed,
        hasMoreComments: sortedFilteredComments.length > initialDisplayCount
      });
    } else {
      // When showAllComments is true, show all comments
      updateState({
        displayedComments: sortedFilteredComments,
        hasMoreComments: false
      });
    }
  }, [sortedFilteredComments, state.showAllComments, updateState]);

  // Reset pagination when search or filter changes
  useEffect(() => {
    updateState({ showAllComments: false, hasMoreComments: true });
  }, [searchQuery, filterType, updateState]);

  // Load comments on mount
  useEffect(() => {
    loadComments();
  }, [targetId]);

  // Auto-expand comment and load all comments if hash points to a comment/reply
  useEffect(() => {
    const hash = window.location.hash;
    if (!hash || !hash.startsWith('#comment-')) return;

    const commentId = hash.replace('#comment-', '');

    // Check if this is a main comment (not a reply)
    const isMainComment = state.comments.some((comment: any) => comment._id === commentId);

    // Check if this is a reply (not a main comment)
    const isReply = state.comments.some((comment: any) =>
      comment.replies?.some((reply: any) => reply._id === commentId) ||
      comment.replies?.some((reply: any) =>
        reply.replies?.some((nested: any) => nested._id === commentId)
      )
    );

    // If it's a main comment and not in displayed comments, load all comments
    if (isMainComment && !state.showAllComments) {
      const isInDisplayed = state.displayedComments.some((comment: any) => comment._id === commentId);
      if (!isInDisplayed) {
        // Load all comments to show the target comment
        updateState({ showAllComments: true });
      }
    }

    // If it's a reply, expand parent comment
    if (isReply) {
      // Find parent comment and expand it
      const parentComment = state.comments.find((comment: any) =>
        comment.replies?.some((reply: any) => reply._id === commentId) ||
        comment.replies?.some((reply: any) =>
          reply.replies?.some((nested: any) => nested._id === commentId)
        )
      );

      if (parentComment && !state.expandedReplies.has(parentComment._id)) {
        handleExpandReplies(parentComment._id);
      }
    }
  }, [state.comments, state.displayedComments, state.showAllComments, state.expandedReplies]);

  // Close menu when clicking outside
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (actions.showMenu && !(event.target as Element).closest('.comment-menu')) {
        closeMenu();
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, [actions.showMenu, closeMenu]);

  // Helper functions
  const getDisplayedReplies = (replies: Comment[], commentId: string) => {
    if (!replies || !Array.isArray(replies)) return [];

    const isExpanded = state.expandedReplies.has(commentId);

    // Mặc định ẩn hết replies, chỉ hiện khi expanded
    if (isExpanded) {
      return replies;
    }

    return []; // Không hiển thị replies nào mặc định
  };

  const shouldShowLoadMoreReplies = (replies: Comment[], commentId: string) => {
    if (!replies || !Array.isArray(replies)) return false;

    const totalReplies = replies.length;
    const isExpanded = state.expandedReplies.has(commentId);

    // Hiện nút "Xem replies" nếu có replies và chưa expanded
    return totalReplies > 0 && !isExpanded;
  };

  const shouldShowCollapseReplies = (replies: Comment[], commentId: string) => {
    if (!replies || !Array.isArray(replies)) return false;

    const totalReplies = replies.length;
    const isExpanded = state.expandedReplies.has(commentId);

    // Hiện nút "Thu gọn" nếu có replies và đã expanded
    return totalReplies > 0 && isExpanded;
  };

  const getTotalRepliesCount = (replies: Comment[]) => {
    if (!replies || !Array.isArray(replies)) return 0;

    let total = replies.length;
    replies.forEach(reply => {
      if (reply.replies && reply.replies.length > 0) {
        total += getTotalRepliesCount(reply.replies);
      }
    });

    return total;
  };

  // Calculate stats
  const stats = useMemo(() => {
    const now = new Date();
    const oneDayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);

    const userCounts: { [key: string]: number } = {};
    let withRepliesCount = 0;
    let mostVotedCount = 0;
    let recentCount = 0;

    state.comments.forEach((comment: any) => {

      const userName = comment.userId?.username || 'Người dùng đã xóa';
      userCounts[userName] = (userCounts[userName] || 0) + 1;

      if (comment.replies && comment.replies.length > 0) {
        withRepliesCount++;
      }

      const score = getVoteScore(comment);
      if (score > 5) {
        mostVotedCount++;
      }

      const commentDate = new Date(comment.createdAt);
      if (commentDate > oneDayAgo) {
        recentCount++;
      }
    });

    return {
      total: state.comments.length,
      withReplies: withRepliesCount,
      mostVoted: mostVotedCount,
      recent: recentCount,
      byUser: userCounts
    };
  }, [state.comments]);

  // Export comments
  const exportComments = () => {
    const exportData = {
      targetId,
      exportDate: new Date().toISOString(),
      totalComments: state.comments.length,
      comments: state.comments.map((comment: any) => ({
        id: comment._id,
        content: comment.content,
        author: comment.userId?.name || comment.userId?.username || 'Người dùng đã xóa',
        createdAt: comment.createdAt,
        upvotes: comment.upvotes?.length || 0,
        downvotes: comment.downvotes?.length || 0,
        replies: comment.replies?.length || 0
      }))
    };

    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `comments_${targetId}_${new Date().toISOString().split('T')[0]}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    toast.success('Đã xuất bình luận thành công!');
  };

  if (state.loading) {
    return (
      <div className="comments-loading">
        <div className="loading-spinner"></div>
        <p>Đang tải bình luận...</p>
      </div>
    );
  }
  console.log('displayedComments', state.displayedComments)
  return (
    <div className="comment-list-container">
      {/* Comment Input - New Layout */}
      <div className="comment-input-section">
        <form onSubmit={handleSubmitComment} className="comment-input-form-new">
          <div className="comment-input-header">
            <img
              src={user?.avatarUrl || '/unknown-avatar.jpg'}
              alt={user?.username || 'Unknown User'}
              className="comment-avatar-small"
            />
            <div className="comment-input-main">
              <input
                type="text"
                value={newComment}
                onChange={(e) => setNewComment(e.target.value)}
                placeholder="Viết bình luận của bạn..."
                className="comment-input-new"
                disabled={state.submitting}
                maxLength={1000}
              />
            </div>
          </div>

          {/* Image Preview */}
          {previewImages.length > 0 && (
            <div className="comment-preview-section">
              <div className="comment-preview-grid">
                {previewImages.map((preview, index) => (
                  <div key={index} className="comment-preview-card">
                    <img src={preview} alt={`preview-${index}`} />
                    <button
                      type="button"
                      className="comment-preview-close"
                      onClick={() => {
                        setPreviewImages(prev => {
                          const filtered = prev.filter((_, i) => i !== index);
                          URL.revokeObjectURL(preview);
                          return filtered;
                        });
                        setUploadedImages(prev => prev.filter((_, i) => i !== index));
                      }}
                      title="Xóa ảnh"
                    >
                      ×
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}

          <div className="comment-input-footer">
            <div className="comment-toolbar">
              <button
                type="button"
                className="comment-toolbar-btn"
                onClick={() => imageInputRef.current?.click()}
                title="Đính kèm ảnh"
              >
                <ImageIcon size={18} />
                <span>Ảnh</span>
              </button>
              <input
                ref={imageInputRef}
                type="file"
                accept="image/*"
                multiple
                style={{ display: 'none' }}
                onChange={(e) => handleImageUpload(e.target.files)}
                aria-label="Tải lên hình ảnh cho bình luận"
                title="Tải lên hình ảnh cho bình luận"
              />

              <button
                type="button"
                ref={stickerButtonRef}
                className="comment-toolbar-btn"
                onClick={handleStickerToggle}
                title="Nhãn dán & GIF"
              >
                <ImageIcon size={18} />
                <span>Sticker</span>
              </button>
            </div>

            <button
              type="submit"
              className="comment-send-btn"
              disabled={(!newComment.trim() && uploadedImages.length === 0) || state.submitting}
              title="Gửi bình luận"
            >
              {state.submitting ? (
                <div className="loading-spinner-small"></div>
              ) : (
                <>
                  <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width={18} height={18} fill="none" stroke="currentColor" strokeWidth="2">
                    <line x1="22" y1="2" x2="11" y2="13"></line>
                    <polygon points="22 2 15 22 11 13 2 9 22 2"></polygon>
                  </svg>
                  <span>Gửi</span>
                </>
              )}
            </button>
          </div>
        </form>
      </div>

      {/* Search and Filter Bar - Collapsible */}
      <div className="search-filter-bar">
        <div className="search-filter-header" onClick={() => setIsFilterBarExpanded(!isFilterBarExpanded)}>
          <div className="search-filter-title">
            <Search size={18} />
            <span>Tìm kiếm & Bộ lọc</span>
          </div>
          <button
            type="button"
            className="search-filter-toggle"
            onClick={(e) => {
              e.stopPropagation();
              setIsFilterBarExpanded(!isFilterBarExpanded);
            }}
            aria-label={isFilterBarExpanded ? "Thu gọn" : "Mở rộng"}
          >
            {isFilterBarExpanded ? <ChevronUp size={18} /> : <ChevronDown size={18} />}
          </button>
        </div>

        <div className={`search-filter-content ${isFilterBarExpanded ? 'expanded' : 'collapsed'}`}>
          <div className="search-section">
            <Search size={20} />
            <input
              type="text"
              placeholder="Tìm kiếm bình luận..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="search-input"
            />
            {searchQuery && (
              <button
                type="button"
                onClick={() => setSearchQuery('')}
                className="clear-search-btn"
                title="Xóa tìm kiếm"
              >
                <span>×</span>
              </button>
            )}
          </div>

          <div className="filter-section">
            <Filter size={20} />
            <select
              value={filterType}
              onChange={(e) => setFilterType(e.target.value as FilterType)}
              className="filter-select"
              aria-label="Lọc bình luận"
              title="Lọc bình luận"
            >
              <option value="all">Tất cả</option>
              <option value="recent">24h qua</option>
              <option value="mostVoted">Nhiều vote</option>
              <option value="withReplies">Có trả lời</option>
            </select>
          </div>

          <div className="sort-section">
            <select
              value={state.sortBy}
              onChange={(e) => handleSortChange(e.target.value as SortType)}
              className="sort-select"
              aria-label="Sắp xếp bình luận"
              title="Sắp xếp bình luận"
            >
              <option value="newest">Mới nhất</option>
              <option value="oldest">Cũ nhất</option>
              <option value="mostVoted">Nhiều vote nhất</option>
            </select>
          </div>
        </div>
      </div>

      {/* Sticker Picker Portal */}
      {showStickerPicker && stickerAnchor && createPortal(
        <StickerPicker
          onSelect={handleStickerSelect}
          onClose={() => setShowStickerPicker(false)}
          anchor={stickerAnchor}
        />,
        document.body
      )}

      {/* Comments List */}
      <div className="comments-container">
        <div className="comments-header">
          <div className="comments-count">
            Hiển thị {state.displayedComments.length} / {sortedFilteredComments.length} bình luận
            {searchQuery.trim() || filterType !== 'all' ? ` (đã lọc từ ${state.comments.length} bình luận)` : ''}
          </div>

          {/* <div className="comments-actions">
            <button
              className="stats-btn"
              onClick={() => setShowStats(!showStats)}
              title="Thống kê bình luận"
            >
              <BarChart3 size={16} />
              <span>Thống kê</span>
            </button>

            <button
              className="export-btn"
              onClick={exportComments}
              title="Xuất bình luận"
            >
              <Download size={16} />
              <span>Xuất</span>
            </button>
          </div> */}
        </div>

        {/* Stats Panel */}
        {showStats && (
          <div className="stats-panel">
            <h4>Thống kê bình luận</h4>
            <div className="stats-grid">
              <div className="stat-item">
                <span className="stat-label">Tổng số:</span>
                <span className="stat-value">{stats.total}</span>
              </div>
              <div className="stat-item">
                <span className="stat-label">Có trả lời:</span>
                <span className="stat-value">{stats.withReplies}</span>
              </div>
              <div className="stat-item">
                <span className="stat-label">Nhiều vote:</span>
                <span className="stat-value">{stats.mostVoted}</span>
              </div>
              <div className="stat-item">
                <span className="stat-label">24h qua:</span>
                <span className="stat-value">{stats.recent}</span>
              </div>
            </div>

            {Object.keys(stats.byUser).length > 0 && (
              <div className="user-stats">
                <h5>Bình luận theo người dùng:</h5>
                {Object.entries(stats.byUser).map(([userName, count]) => (
                  <div key={userName} className="user-stat-item">
                    <span className="user-name">{userName}</span>
                    <span className="user-count">{count}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Comments */}
        {state.displayedComments.length === 0 ? (
          <div className="no-comments">
            <MessageCircle size={24} />
            <p>Chưa có bình luận nào. Hãy là người đầu tiên!</p>
          </div>
        ) : (
          state.displayedComments.map((comment: any) => (
            <div key={comment._id} id={`comment-${comment._id}`} className="comment-item">
              <div className="comment-avatar">
                {comment.userId ? (
                  comment.userId._id === user?._id ? (
                    <img
                      src={comment.userId.avatarUrl || '/default-avatar.png'}
                      alt={comment.userId.username || 'Người dùng đã xóa'}
                    />
                  ) : (
                    <button
                      onClick={() => openChat(comment.userId._id, {
                        username: comment.userId.username,
                        avatarUrl: comment.userId.avatarUrl
                      })}
                      className="comment-avatar-btn-trigger"
                      style={{ background: 'none', border: 'none', padding: 0, margin: 0, cursor: 'pointer', display: 'block', borderRadius: '50%', overflow: 'hidden', width: '100%', height: '100%' }}
                      title={`Nhắn tin với ${comment.userId.name || comment.userId.username}`}
                    >
                      <img
                        src={comment.userId.avatarUrl || '/default-avatar.png'}
                        alt={comment.userId.username || 'Người dùng đã xóa'}
                        style={{ display: 'block', width: '100%', height: '100%', objectFit: 'cover' }}
                      />
                    </button>
                  )
                ) : (
                  <img
                    src="/default-avatar.png"
                    alt="Người dùng đã xóa"
                  />
                )}
              </div>
              <div className="comment-content">
                <div className="comment-header">
                  <div className="comment-author-row">
                    {comment.userId ? (
                      <Link href={`/profile/${comment.userId.username || comment.userId._id}`} className="comment-author-link">
                        <span className="comment-author">{comment.userId.name || comment.userId.username || 'Người dùng đã xóa'}</span>
                      </Link>
                    ) : (
                      <span className="comment-author deleted-user" style={{ color: '#888', fontStyle: 'italic' }}>Người dùng đã xóa</span>
                    )}
                    {authorId && comment.userId && comment.userId._id === authorId && (
                      <span className="author-badge">Tác giả</span>
                    )}
                    {comment.isBest && (
                      <span className="best-answer-badge">Câu trả lời hay nhất</span>
                    )}
                  </div>
                  <div className="comment-time">{formatTime(comment.createdAt)}</div>
                </div>

                <div
                  className="comment-text"
                  dangerouslySetInnerHTML={{
                    __html: (() => {
                      if (!comment?.content) return '';
                      let content = String(comment.content);

                      // Unescape HTML entities nếu content bị escape
                      if (content.includes('&lt;') || content.includes('&gt;') || content.includes('&amp;')) {
                        content = content
                          .replace(/&lt;/g, '<')
                          .replace(/&gt;/g, '>')
                          .replace(/&amp;/g, '&')
                          .replace(/&quot;/g, '"')
                          .replace(/&#39;/g, "'")
                          .replace(/&#x27;/g, "'")
                          .replace(/&#x2F;/g, '/');
                      }

                      // Convert URL Giphy dạng text thành <img> tag
                      const giphyUrlPattern = /https?:\/\/(?:media\d?\.)?giphy\.com\/media\/[^\s<>"'\)\]&]+/gi;
                      const giphyUrls = content.match(giphyUrlPattern);

                      if (giphyUrls && giphyUrls.length > 0) {
                        const uniqueUrls = [...new Set(giphyUrls)].sort((a, b) => b.length - a.length);

                        uniqueUrls.forEach((url: string) => {
                          const cleanUrl = url.trim();
                          const escaped = cleanUrl.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

                          // Bỏ qua nếu URL đã nằm trong thẻ <img> src
                          if (new RegExp(`<img[^>]+src=["']${escaped}`, 'i').test(content)) {
                            return;
                          }

                          const imgTag = `<img src="${cleanUrl}" alt="sticker" style="max-width: 150px; max-height: 150px; border-radius: 8px; margin: 8px 0; display: block;" />`;

                          // Replace URL trong content
                          content = content.replace(new RegExp(escaped, 'gi'), (match, offset, string) => {
                            const before = string.substring(0, offset);
                            const lastOpen = before.lastIndexOf('<');
                            const lastClose = before.lastIndexOf('>');

                            if (lastOpen > lastClose) {
                              const tagPart = before.substring(lastOpen);
                              const doubleQuotes = (tagPart.match(/"/g) || []).length;
                              const singleQuotes = (tagPart.match(/'/g) || []).length;
                              if (doubleQuotes % 2 !== 0 || singleQuotes % 2 !== 0) {
                                return match;
                              }
                            }

                            return imgTag;
                          });
                        });
                      }

                      return content;
                    })()
                  }}
                ></div>

                <div className="comment-actions">
                  {/* Vote buttons */}
                  <div className="vote-buttons-horizontal">
                    <button
                      className={`vote-btn upvote ${getVoteStatus(comment) === 'upvoted' ? 'active' : ''}`}
                      onClick={() => handleVote(comment._id, 'upvote')}
                      title="Upvote"
                    >
                      <ArrowUp size={16} />
                    </button>
                    <span className="vote-score">{getVoteScore(comment)}</span>
                    <button
                      className={`vote-btn downvote ${getVoteStatus(comment) === 'downvoted' ? 'active' : ''}`}
                      onClick={() => handleVote(comment._id, 'downvote')}
                      title="Downvote"
                    >
                      <ArrowDown size={16} />
                    </button>
                  </div>

                  <button
                    className="comment-action-btn"
                    onClick={() => startReply(comment._id)}
                  >
                    <Reply size={14} />
                    <span>Trả lời</span>
                  </button>

                  {(comment.userId?._id || comment.userId) !== user?._id && (
                    <ReportButton
                      itemId={comment._id}
                      itemType="comment"
                      onReported={() => { }}
                    />
                  )}

                  {/* Menu cho xóa */}
                  {canDeleteComment(comment, user?._id) && (
                    <div className="comment-menu">
                      <button
                        className="comment-menu-btn"
                        onClick={(e) => {
                          e.stopPropagation();
                          toggleMenu(actions.showMenu === comment._id ? null : comment._id);
                        }}
                        title="Tùy chọn"
                      >
                        <MoreVertical size={14} />
                      </button>

                      {actions.showMenu === comment._id && (
                        <div className="comment-menu-dropdown">
                          <button
                            className="comment-menu-item comment-menu-item-danger"
                            onClick={(e) => {
                              e.stopPropagation();
                              handleDeleteComment(comment._id);
                              closeMenu();
                            }}
                          >
                            <Trash2 size={14} />
                            <span>Xóa</span>
                          </button>
                        </div>
                      )}
                    </div>
                  )}
                </div>

                {/* Reply Input - New Layout */}
                {actions.replyingTo === comment._id && (
                  <div className="reply-input-section-new">
                    <form onSubmit={handleSubmitReply} className="reply-input-form-new">
                      <div className="reply-input-header">
                        <img
                          src={user?.avatarUrl || '/unknown-avatar.jpg'}
                          alt={user?.username || 'Unknown User'}
                          className="reply-avatar-small"
                        />
                        <div className="reply-input-main">
                          <input
                            type="text"
                            value={actions.replyContent}
                            onChange={(e) => updateReplyContent(e.target.value)}
                            placeholder={`Trả lời ${comment.userId?.name || comment.userId?.username || 'Người dùng đã xóa'}...`}
                            className="reply-input-new"
                            disabled={state.submitting}
                            maxLength={1000}
                          />
                        </div>
                      </div>

                      {/* Reply Image Preview */}
                      {actions.replyingTo && replyPreviewImages[actions.replyingTo] && replyPreviewImages[actions.replyingTo].length > 0 && (
                        <div className="reply-preview-section">
                          <div className="reply-preview-grid">
                            {replyPreviewImages[actions.replyingTo].map((preview, index) => (
                              <div key={index} className="reply-preview-card">
                                <img src={preview} alt={`preview-${index}`} />
                                <button
                                  type="button"
                                  className="reply-preview-close"
                                  onClick={() => {
                                    const replyId = actions.replyingTo!;
                                    setReplyPreviewImages(prev => {
                                      const filtered = (prev[replyId] || []).filter((_: string, i: number) => i !== index);
                                      URL.revokeObjectURL(preview);
                                      return { ...prev, [replyId]: filtered };
                                    });
                                    setReplyImages(prev => ({
                                      ...prev,
                                      [replyId]: (prev[replyId] || []).filter((_: string, i: number) => i !== index)
                                    }));
                                  }}
                                  title="Xóa ảnh"
                                >
                                  ×
                                </button>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      <div className="reply-input-footer">
                        <div className="reply-toolbar">
                          <button
                            type="button"
                            className="reply-toolbar-btn"
                            onClick={() => {
                              if (!actions.replyingTo) return;
                              const input = replyImageInputRefs.current[actions.replyingTo];
                              if (input) input.click();
                              else {
                                const replyId = actions.replyingTo;
                                const newInput = document.createElement('input');
                                newInput.type = 'file';
                                newInput.accept = 'image/*';
                                newInput.multiple = true;
                                newInput.style.display = 'none';
                                newInput.onchange = (e) => handleReplyImageUpload(replyId, (e.target as HTMLInputElement).files);
                                document.body.appendChild(newInput);
                                newInput.click();
                                replyImageInputRefs.current[replyId] = newInput;
                              }
                            }}
                            title="Đính kèm ảnh"
                          >
                            <ImageIcon size={16} />
                            <span>Ảnh</span>
                          </button>
                          <input
                            ref={(el) => {
                              if (actions.replyingTo) {
                                replyImageInputRefs.current[actions.replyingTo] = el;
                              }
                            }}
                            type="file"
                            accept="image/*"
                            multiple
                            style={{ display: 'none' }}
                            aria-label="Tải lên hình ảnh cho phản hồi"
                            title="Tải lên hình ảnh cho phản hồi"
                            onChange={(e) => {
                              if (actions.replyingTo) {
                                handleReplyImageUpload(actions.replyingTo, e.target.files);
                              }
                            }}
                          />

                          <button
                            type="button"
                            ref={(el) => {
                              if (actions.replyingTo) {
                                replyStickerButtonRefs.current[actions.replyingTo] = el;
                              }
                            }}
                            className="reply-toolbar-btn"
                            onClick={() => {
                              if (actions.replyingTo) {
                                handleReplyStickerToggle(actions.replyingTo);
                              }
                            }}
                            title="Nhãn dán & GIF"
                          >
                            <ImageIcon size={16} />
                            <span>Sticker</span>
                          </button>
                        </div>

                        <div className="reply-actions-group">
                          <button
                            type="button"
                            className="reply-cancel-btn"
                            onClick={cancelReply}
                          >
                            Hủy
                          </button>
                          <button
                            type="submit"
                            className="reply-send-btn"
                            disabled={(!actions.replyContent.trim() && !(actions.replyingTo && replyImages[actions.replyingTo]?.length)) || state.submitting}
                            title="Gửi trả lời"
                          >
                            {state.submitting ? (
                              <div className="loading-spinner-small"></div>
                            ) : (
                              <>
                                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width={16} height={16} fill="none" stroke="currentColor" strokeWidth="2">
                                  <line x1="22" y1="2" x2="11" y2="13"></line>
                                  <polygon points="22 2 15 22 11 13 2 9 22 2"></polygon>
                                </svg>
                                <span>Gửi</span>
                              </>
                            )}
                          </button>
                        </div>
                      </div>
                    </form>

                    {/* Reply Sticker Picker */}
                    {actions.replyingTo && replyStickerPickers[actions.replyingTo] && replyStickerAnchors.current[actions.replyingTo] && (() => {
                      const replyId = actions.replyingTo;
                      return createPortal(
                        <StickerPicker
                          onSelect={(gifUrl: string) => handleReplyStickerSelect(replyId, gifUrl)}
                          onClose={() => setReplyStickerPickers(prev => ({ ...prev, [replyId]: false }))}
                          anchor={replyStickerAnchors.current[replyId] || undefined}
                        />,
                        document.body
                      );
                    })()}
                  </div>
                )}

                {/* Hiển thị replies */}
                {comment.replies && Array.isArray(comment.replies) && comment.replies.length > 0 && (
                  <div className="comment-replies">
                    <div>
                      {getDisplayedReplies(comment.replies, comment._id).map((reply) => (
                        <div key={reply._id} id={`comment-${reply._id}`} className="reply-item">
                          <div className="reply-avatar">
                            {reply.userId ? (
                              reply.userId._id === user?._id ? (
                                <img
                                  src={reply.userId.avatarUrl || '/default-avatar.png'}
                                  alt={reply.userId.name || reply.userId.username || 'Người dùng đã xóa'}
                                />
                              ) : (
                                <button
                                  onClick={() => openChat(reply.userId._id, {
                                    username: reply.userId.username,
                                    avatarUrl: reply.userId.avatarUrl
                                  })}
                                  className="comment-avatar-btn-trigger"
                                  style={{ background: 'none', border: 'none', padding: 0, margin: 0, cursor: 'pointer', display: 'block', borderRadius: '50%', overflow: 'hidden', width: '100%', height: '100%' }}
                                  title={`Nhắn tin với ${reply.userId.name || reply.userId.username}`}
                                >
                                  <img
                                    src={reply.userId.avatarUrl || '/default-avatar.png'}
                                    alt={reply.userId.name || reply.userId.username || 'Người dùng đã xóa'}
                                    style={{ display: 'block', width: '100%', height: '100%', objectFit: 'cover' }}
                                  />
                                </button>
                              )
                            ) : (
                              <img
                                src="/default-avatar.png"
                                alt="Người dùng đã xóa"
                              />
                            )}
                          </div>
                          <div className="reply-content">
                            <div className="reply-header">
                              <div className="reply-author-row">
                                {reply.userId ? (
                                  <Link href={`/profile/${reply.userId.username || reply.userId._id}`} className="reply-author-link">
                                    <span className="reply-author">{reply.userId.name || reply.userId.username || 'Người dùng đã xóa'}</span>
                                  </Link>
                                ) : (
                                  <span className="reply-author deleted-user" style={{ color: '#888', fontStyle: 'italic' }}>Người dùng đã xóa</span>
                                )}
                                {authorId && reply.userId && reply.userId._id === authorId && (
                                  <span className="author-badge">Tác giả</span>
                                )}
                              </div>
                              <div className="reply-time">{formatTime(reply.createdAt)}</div>
                            </div>
                            <div
                              className="reply-text"
                              dangerouslySetInnerHTML={{
                                __html: (() => {
                                  if (!reply?.content) return '';
                                  let content = String(reply.content);

                                  // Unescape HTML entities
                                  if (content.includes('&lt;') || content.includes('&gt;') || content.includes('&amp;')) {
                                    content = content
                                      .replace(/&lt;/g, '<')
                                      .replace(/&gt;/g, '>')
                                      .replace(/&amp;/g, '&')
                                      .replace(/&quot;/g, '"')
                                      .replace(/&#39;/g, "'")
                                      .replace(/&#x27;/g, "'")
                                      .replace(/&#x2F;/g, '/');
                                  }

                                  // Convert Giphy URLs
                                  const giphyUrlPattern = /https?:\/\/(?:media\d?\.)?giphy\.com\/media\/[^\s<>"'\)\]&]+/gi;
                                  const giphyUrls = content.match(giphyUrlPattern);

                                  if (giphyUrls && giphyUrls.length > 0) {
                                    const uniqueUrls = [...new Set(giphyUrls)].sort((a, b) => b.length - a.length);
                                    uniqueUrls.forEach((url: string) => {
                                      const cleanUrl = url.trim();
                                      const escaped = cleanUrl.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
                                      if (!new RegExp(`<img[^>]+src=["']${escaped}`, 'i').test(content)) {
                                        const imgTag = `<img src="${cleanUrl}" alt="sticker" style="max-width: 150px; max-height: 150px; border-radius: 8px; margin: 8px 0; display: block;" />`;
                                        content = content.replace(new RegExp(escaped, 'gi'), (match, offset, string) => {
                                          const before = string.substring(0, offset);
                                          const lastOpen = before.lastIndexOf('<');
                                          const lastClose = before.lastIndexOf('>');
                                          if (lastOpen > lastClose) {
                                            const tagPart = before.substring(lastOpen);
                                            if ((tagPart.match(/"/g) || []).length % 2 !== 0 || (tagPart.match(/'/g) || []).length % 2 !== 0) {
                                              return match;
                                            }
                                          }
                                          return imgTag;
                                        });
                                      }
                                    });
                                  }

                                  return content;
                                })()
                              }}
                            ></div>
                            <div className="reply-actions">
                              {/* Vote buttons for replies */}
                              <div className="vote-buttons-horizontal">
                                <button
                                  className={`vote-btn upvote ${getVoteStatus(reply) === 'upvoted' ? 'active' : ''}`}
                                  onClick={() => handleVote(reply._id, 'upvote')}
                                  title="Upvote"
                                >
                                  <ArrowUp size={12} />
                                </button>
                                <span className="vote-score">{getVoteScore(reply)}</span>
                                <button
                                  className={`vote-btn downvote ${getVoteStatus(reply) === 'downvoted' ? 'active' : ''}`}
                                  onClick={() => handleVote(reply._id, 'downvote')}
                                  title="Downvote"
                                >
                                  <ArrowDown size={12} />
                                </button>
                              </div>

                              <button
                                className="reply-action-btn"
                                onClick={() => startReplyToReply(reply._id)}
                              >
                                <Reply size={12} />
                                <span>Trả lời</span>
                              </button>

                              {/* Menu cho xóa reply */}
                              {canDeleteComment(reply, user?._id) && (
                                <div className="reply-menu">
                                  <button
                                    className="reply-menu-btn"
                                    onClick={() => toggleMenu(actions.showMenu === reply._id ? null : reply._id)}
                                  >
                                    <MoreVertical size={12} />
                                  </button>

                                  {actions.showMenu === reply._id && (
                                    <div className="reply-menu-dropdown">
                                      <button
                                        className="reply-menu-item reply-menu-item-danger"
                                        onClick={() => {
                                          handleDeleteComment(reply._id);
                                          closeMenu();
                                        }}
                                      >
                                        <Trash2 size={12} />
                                        <span>Xóa</span>
                                      </button>
                                    </div>
                                  )}
                                </div>
                              )}
                            </div>

                            {/* Reply to reply input */}
                            {actions.replyToReply === reply._id && (
                              <div className="reply-to-reply-input-new">
                                <form onSubmit={handleSubmitReplyToReply} className="reply-input-form-new">
                                  <div className="reply-input-header">
                                    <img
                                      src={user?.avatarUrl || '/unknown-avatar.jpg'}
                                      alt={user?.username || 'Unknown User'}
                                      className="reply-avatar-small"
                                    />
                                    <div className="reply-input-main">
                                      <input
                                        type="text"
                                        value={actions.replyToReplyContent}
                                        onChange={(e) => updateReplyToReplyContent(e.target.value)}
                                        placeholder={`Trả lời ${reply.userId?.name || reply.userId?.username || 'Người dùng đã xóa'}...`}
                                        className="reply-input-new"
                                        disabled={state.submitting}
                                        maxLength={1000}
                                      />
                                    </div>
                                  </div>

                                  {/* Reply-to-Reply Image Preview */}
                                  {actions.replyToReply && replyPreviewImages[actions.replyToReply] && replyPreviewImages[actions.replyToReply].length > 0 && (
                                    <div className="reply-preview-section">
                                      <div className="reply-preview-grid">
                                        {replyPreviewImages[actions.replyToReply].map((preview, index) => (
                                          <div key={index} className="reply-preview-card">
                                            <img src={preview} alt={`preview-${index}`} />
                                            <button
                                              type="button"
                                              className="reply-preview-close"
                                              onClick={() => {
                                                const replyId = actions.replyToReply!;
                                                setReplyPreviewImages(prev => {
                                                  const filtered = (prev[replyId] || []).filter((_: string, i: number) => i !== index);
                                                  URL.revokeObjectURL(preview);
                                                  return { ...prev, [replyId]: filtered };
                                                });
                                                setReplyImages(prev => ({
                                                  ...prev,
                                                  [replyId]: (prev[replyId] || []).filter((_: string, i: number) => i !== index)
                                                }));
                                              }}
                                              title="Xóa ảnh"
                                            >
                                              ×
                                            </button>
                                          </div>
                                        ))}
                                      </div>
                                    </div>
                                  )}

                                  <div className="reply-input-footer">
                                    <div className="reply-toolbar">
                                      <button
                                        type="button"
                                        className="reply-toolbar-btn"
                                        onClick={() => {
                                          if (!actions.replyToReply) return;
                                          const input = replyImageInputRefs.current[actions.replyToReply];
                                          if (input) input.click();
                                          else {
                                            const replyId = actions.replyToReply;
                                            const newInput = document.createElement('input');
                                            newInput.type = 'file';
                                            newInput.accept = 'image/*';
                                            newInput.multiple = true;
                                            newInput.style.display = 'none';
                                            newInput.onchange = (e) => handleReplyImageUpload(replyId, (e.target as HTMLInputElement).files);
                                            document.body.appendChild(newInput);
                                            newInput.click();
                                            replyImageInputRefs.current[replyId] = newInput;
                                          }
                                        }}
                                        title="Đính kèm ảnh"
                                      >
                                        <ImageIcon size={16} />
                                        <span>Ảnh</span>
                                      </button>
                                      <input
                                        ref={(el) => {
                                          if (actions.replyToReply) {
                                            replyImageInputRefs.current[actions.replyToReply] = el;
                                          }
                                        }}
                                        type="file"
                                        accept="image/*"
                                        multiple
                                        style={{ display: 'none' }}
                                        aria-label="Tải lên hình ảnh cho phản hồi lồng nhau"
                                        title="Tải lên hình ảnh cho phản hồi lồng nhau"
                                        onChange={(e) => {
                                          if (actions.replyToReply) {
                                            handleReplyImageUpload(actions.replyToReply, e.target.files);
                                          }
                                        }}
                                      />

                                      <button
                                        type="button"
                                        ref={(el) => {
                                          if (actions.replyToReply) {
                                            replyStickerButtonRefs.current[actions.replyToReply] = el;
                                          }
                                        }}
                                        className="reply-toolbar-btn"
                                        onClick={() => {
                                          if (actions.replyToReply) {
                                            handleReplyStickerToggle(actions.replyToReply);
                                          }
                                        }}
                                        title="Nhãn dán & GIF"
                                      >
                                        <ImageIcon size={16} />
                                        <span>Sticker</span>
                                      </button>
                                    </div>

                                    <div className="reply-actions-group">
                                      <button
                                        type="button"
                                        className="reply-cancel-btn"
                                        onClick={cancelReplyToReply}
                                      >
                                        Hủy
                                      </button>
                                      <button
                                        type="submit"
                                        className="reply-send-btn"
                                        disabled={(!actions.replyToReplyContent.trim() && !(actions.replyToReply && replyImages[actions.replyToReply]?.length)) || state.submitting}
                                        title="Gửi trả lời"
                                      >
                                        {state.submitting ? (
                                          <div className="loading-spinner-small"></div>
                                        ) : (
                                          <>
                                            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width={16} height={16} fill="none" stroke="currentColor" strokeWidth="2">
                                              <line x1="22" y1="2" x2="11" y2="13"></line>
                                              <polygon points="22 2 15 22 11 13 2 9 22 2"></polygon>
                                            </svg>
                                            <span>Gửi</span>
                                          </>
                                        )}
                                      </button>
                                    </div>
                                  </div>
                                </form>

                                {/* Reply-to-Reply Sticker Picker */}
                                {actions.replyToReply && replyStickerPickers[actions.replyToReply] && replyStickerAnchors.current[actions.replyToReply] && (() => {
                                  const replyId = actions.replyToReply;
                                  return createPortal(
                                    <StickerPicker
                                      onSelect={(gifUrl: string) => handleReplyStickerSelect(replyId, gifUrl)}
                                      onClose={() => setReplyStickerPickers(prev => ({ ...prev, [replyId]: false }))}
                                      anchor={replyStickerAnchors.current[replyId] || undefined}
                                    />,
                                    document.body
                                  );
                                })()}
                              </div>
                            )}

                            {/* Nested replies */}
                            {reply.replies && Array.isArray(reply.replies) && reply.replies.length > 0 && (
                              <div className="nested-replies">
                                {reply.replies.map((nestedReply: any) => (
                                  <div key={nestedReply._id} id={`comment-${nestedReply._id}`} className="nested-reply-item">
                                    <div className="nested-reply-avatar">
                                      {nestedReply.userId ? (
                                        nestedReply.userId._id === user?._id ? (
                                          <img
                                            src={nestedReply.userId.avatarUrl || '/default-avatar.png'}
                                            alt={nestedReply.userId.name || nestedReply.userId.username || 'Người dùng đã xóa'}
                                          />
                                        ) : (
                                          <button
                                            onClick={() => openChat(nestedReply.userId._id, {
                                              username: nestedReply.userId.username,
                                              avatarUrl: nestedReply.userId.avatarUrl
                                            })}
                                            className="comment-avatar-btn-trigger"
                                            style={{ background: 'none', border: 'none', padding: 0, margin: 0, cursor: 'pointer', display: 'block', borderRadius: '50%', overflow: 'hidden', width: '100%', height: '100%' }}
                                            title={`Nhắn tin với ${nestedReply.userId.name || nestedReply.userId.username}`}
                                          >
                                            <img
                                              src={nestedReply.userId.avatarUrl || '/default-avatar.png'}
                                              alt={nestedReply.userId.name || nestedReply.userId.username || 'Người dùng đã xóa'}
                                              style={{ display: 'block', width: '100%', height: '100%', objectFit: 'cover' }}
                                            />
                                          </button>
                                        )
                                      ) : (
                                        <img
                                          src="/default-avatar.png"
                                          alt="Người dùng đã xóa"
                                        />
                                      )}
                                    </div>
                                    <div className="nested-reply-content">
                                      <div className="nested-reply-header">
                                        <div className="nested-reply-author-row">
                                          {nestedReply.userId ? (
                                            <Link href={`/profile/${nestedReply.userId.username || nestedReply.userId._id}`} className="nested-reply-author-link">
                                              <span className="nested-reply-author">{nestedReply.userId.name || nestedReply.userId.username || 'Người dùng đã xóa'}</span>
                                            </Link>
                                          ) : (
                                            <span className="nested-reply-author deleted-user" style={{ color: '#888', fontStyle: 'italic' }}>Người dùng đã xóa</span>
                                          )}
                                          {authorId && nestedReply.userId && nestedReply.userId._id === authorId && (
                                            <span className="author-badge">Tác giả</span>
                                          )}
                                        </div>
                                        <div className="nested-reply-time">{formatTime(nestedReply.createdAt)}</div>
                                      </div>
                                      <div
                                        className="nested-reply-text"
                                        dangerouslySetInnerHTML={{
                                          __html: (() => {
                                            if (!nestedReply?.content) return '';
                                            let content = String(nestedReply.content);

                                            // Unescape HTML entities
                                            if (content.includes('&lt;') || content.includes('&gt;') || content.includes('&amp;')) {
                                              content = content
                                                .replace(/&lt;/g, '<')
                                                .replace(/&gt;/g, '>')
                                                .replace(/&amp;/g, '&')
                                                .replace(/&quot;/g, '"')
                                                .replace(/&#39;/g, "'")
                                                .replace(/&#x27;/g, "'")
                                                .replace(/&#x2F;/g, '/');
                                            }

                                            // Convert Giphy URLs
                                            const giphyUrlPattern = /https?:\/\/(?:media\d?\.)?giphy\.com\/media\/[^\s<>"'\)\]&]+/gi;
                                            const giphyUrls = content.match(giphyUrlPattern);

                                            if (giphyUrls && giphyUrls.length > 0) {
                                              const uniqueUrls = [...new Set(giphyUrls)].sort((a, b) => b.length - a.length);
                                              uniqueUrls.forEach((url: string) => {
                                                const cleanUrl = url.trim();
                                                const escaped = cleanUrl.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
                                                if (!new RegExp(`<img[^>]+src=["']${escaped}`, 'i').test(content)) {
                                                  const imgTag = `<img src="${cleanUrl}" alt="sticker" style="max-width: 150px; max-height: 150px; border-radius: 8px; margin: 8px 0; display: block;" />`;
                                                  content = content.replace(new RegExp(escaped, 'gi'), (match, offset, string) => {
                                                    const before = string.substring(0, offset);
                                                    const lastOpen = before.lastIndexOf('<');
                                                    const lastClose = before.lastIndexOf('>');
                                                    if (lastOpen > lastClose) {
                                                      const tagPart = before.substring(lastOpen);
                                                      if ((tagPart.match(/"/g) || []).length % 2 !== 0 || (tagPart.match(/'/g) || []).length % 2 !== 0) {
                                                        return match;
                                                      }
                                                    }
                                                    return imgTag;
                                                  });
                                                }
                                              });
                                            }

                                            return content;
                                          })()
                                        }}
                                      ></div>
                                      <div className="nested-reply-actions">
                                        {/* Vote buttons for nested replies */}
                                        <div className="vote-buttons-horizontal">
                                          <button
                                            className={`vote-btn upvote ${getVoteStatus(nestedReply) === 'upvoted' ? 'active' : ''}`}
                                            onClick={() => handleVote(nestedReply._id, 'upvote')}
                                            title="Upvote"
                                          >
                                            <ArrowUp size={10} />
                                          </button>
                                          <span className="vote-score">{getVoteScore(nestedReply)}</span>
                                          <button
                                            className={`vote-btn downvote ${getVoteStatus(nestedReply) === 'downvoted' ? 'active' : ''}`}
                                            onClick={() => handleVote(nestedReply._id, 'downvote')}
                                            title="Downvote"
                                          >
                                            <ArrowDown size={10} />
                                          </button>
                                        </div>

                                        {/* Menu cho xóa nested reply */}
                                        {canDeleteComment(nestedReply, user?._id) && (
                                          <div className="nested-reply-menu">
                                            <button
                                              className="nested-reply-menu-btn"
                                              onClick={() => toggleMenu(actions.showMenu === nestedReply._id ? null : nestedReply._id)}
                                            >
                                              <MoreVertical size={10} />
                                            </button>

                                            {actions.showMenu === nestedReply._id && (
                                              <div className="nested-reply-menu-dropdown">
                                                <button
                                                  className="nested-reply-menu-item nested-reply-menu-item-danger"
                                                  onClick={() => {
                                                    handleDeleteComment(nestedReply._id);
                                                    closeMenu();
                                                  }}
                                                >
                                                  <Trash2 size={10} />
                                                  <span>Xóa</span>
                                                </button>
                                              </div>
                                            )}
                                          </div>
                                        )}
                                      </div>
                                    </div>
                                  </div>
                                ))}
                              </div>
                            )}
                          </div>
                        </div>
                      ))}

                      {/* Load More Replies Button */}
                      {shouldShowLoadMoreReplies(comment.replies, comment._id) && (
                        <button
                          className="load-more-replies-btn"
                          onClick={() => handleExpandReplies(comment._id)}
                        >
                          Xem {getTotalRepliesCount(comment.replies)} trả lời
                        </button>
                      )}

                      {/* Collapse Replies Button */}
                      {shouldShowCollapseReplies(comment.replies, comment._id) && (
                        <button
                          className="collapse-replies-btn"
                          onClick={() => handleCollapseReplies(comment._id)}
                        >
                          Thu gọn
                        </button>
                      )}
                    </div>
                  </div>
                )}
              </div>
            </div>
          ))
        )}

        {/* Load More Comments Button */}
        {state.hasMoreComments && !state.showAllComments && (
          <button
            className="load-more-comments-btn"
            onClick={handleLoadMoreComments}
            disabled={state.loading}
          >
            {state.loading ? 'Đang tải...' : `Xem thêm ${sortedFilteredComments.length - state.displayedComments.length} bình luận`}
          </button>
        )}
      </div>

      {/* Delete Confirmation Dialog */}
      <ConfirmDialog
        isOpen={showDeleteConfirm}
        title="Xóa bình luận"
        message="Bạn có chắc chắn muốn xóa bình luận này? Hành động này không thể hoàn tác."
        confirmText="Xóa"
        cancelText="Hủy"
        type="danger"
        onConfirm={confirmDeleteComment}
        onCancel={() => {
          setShowDeleteConfirm(false);
          setCommentToDelete(null);
        }}
      />
    </div>
  );
};

export default CommentList;