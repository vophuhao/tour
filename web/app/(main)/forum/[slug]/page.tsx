/* eslint-disable prefer-const */
/* eslint-disable react-hooks/rules-of-hooks */
"use client";
/* eslint-disable @next/next/no-img-element */
/* eslint-disable @typescript-eslint/no-explicit-any */
import React, { useState, useEffect } from 'react';
import { useParams, useRouter } from 'next/navigation';
import Link from 'next/link';
import { FaHeart, FaBookmark } from 'react-icons/fa';
import { FiArrowLeft, FiMessageSquare } from 'react-icons/fi';
import { forumApi } from '../../../../lib/forumApi';
// import { userApi } from '../../services/api/user';
import formatDistanceToNow from 'date-fns/formatDistanceToNow';
import vi from 'date-fns/locale/vi';
import { toast } from 'sonner';
import Loader from "../../../../components/forum/ui/Loader";
import ReportButton from '../../../../components/forum/ui/ReportButton';
import CommentList from '../../../../components/forum/ui/CommentList';
import { ConfirmDialog } from '../../../../components/forum/ui/ConfirmDialog';
import RichTextEditor from '../../../../components/forum/ui/RichTextEditor';
import { useAuthStore } from '@/store/auth.store';
import { useChatModal } from '@/store/chatstore';

const ForumPostDetail: React.FC = () => {
  const { openChat } = useChatModal();
  const { slug } = useParams<{ slug: string }>();
  const router = useRouter();
  const [post, setPost] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [isLiked, setIsLiked] = useState(false);
  const [isBookmarked, setIsBookmarked] = useState(false);
  const [likeCount, setLikeCount] = useState(0);
  const [saveCount, setSaveCount] = useState(0);
  const [commentCount, setCommentCount] = useState(0);
  const [viewCount, setViewCount] = useState(0);
  const [isEditing, setIsEditing] = useState(false);
  const [editTitle, setEditTitle] = useState('');
  const [editContent, setEditContent] = useState('');
  const [editSlug, setEditSlug] = useState('');
  const [editSummary, setEditSummary] = useState('');
  const [editSubject, setEditSubject] = useState('');
  const [editTags, setEditTags] = useState<string[]>([]);
  const [editCoverImage, setEditCoverImage] = useState<File | null>(null);
  const [isFollowing, setIsFollowing] = useState(false);
  const [followersCount, setFollowersCount] = useState(0);
  const [authorStats, setAuthorStats] = useState<{
    documentsCount: number;
    postsCount: number;
    points: number;
    followersCount?: number;
  } | null>(null);
  const [relatedPosts, setRelatedPosts] = useState<any[]>([]);
  const [loadingRelated, setLoadingRelated] = useState(false);
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);

  // Thêm ref để track request đang chạy
  const fetchingRef = React.useRef(false);

  // Thêm ref để track view đã được tăng cho post này
  const viewedPostsRef = React.useRef<Set<string>>(new Set());
  const hasScrolledToCommentRef = React.useRef(false);
  const { user } = useAuthStore();
  if (!slug) {
    return <div style={{ padding: 32, textAlign: 'center', color: '#ef4444', fontWeight: 600 }}>Không tìm thấy bài viết hoặc đường dẫn không hợp lệ.</div>;
  }

  // Helper function to get current user
  const getCurrentUser = () => {
    const userStr = user?._id ? JSON.stringify(user) : null;
    if (userStr) {
      try {
        return JSON.parse(userStr);
      } catch { }
    }
    return null;
  };

  // Helper function to get category name in Vietnamese
  const getCategoryName = (category: string) => {
    if (!category) return 'Chủ đề khác';
    const names: { [key: string]: string } = {

      'camping-experience': 'Kinh nghiệm cắm trại',
      'camping-gear': 'Đồ dùng dã ngoại',
      'beautiful-places': 'Địa điểm đẹp',
      'outdoor-cuisine': 'Ẩm thực ngoài trời',
      'trip-sharing': 'Chia sẻ hành trình',
      'qna-support': 'Hỏi đáp & Hỗ trợ',
      'other': 'Khác',
      'kinh nghiệm cắm trại': 'Kinh nghiệm cắm trại',
      'đồ dùng dã ngoại': 'Đồ dùng dã ngoại',
      'địa điểm đẹp': 'Địa điểm đẹp',
      'ẩm thực ngoài trời': 'Ẩm thực ngoài trời',
      'chia sẻ hành trình': 'Chia sẻ hành trình',
      'hỏi đáp & hỗ trợ': 'Hỏi đáp & Hỗ trợ',
      'khác': 'Khác',
      'default': category
    };
    return names[category.toLowerCase()] || names.default;
  };

  // Load related posts
  const loadRelatedPosts = async (currentPost: any) => {
    try {
      setLoadingRelated(true);
      const category = currentPost.category || currentPost.subject;
      const currentPostId = currentPost._id;

      // Get posts from same category/subject, excluding current post
      const response = await forumApi.getPosts(1, 5, '', category);
      const posts = response.data?.posts || response.data?.data || [];

      // Filter out current post and limit to 4 posts
      const filtered = posts
        .filter((p: any) => p._id !== currentPostId && p.status === 'active')
        .slice(0, 4);

      setRelatedPosts(filtered);
    } catch (error) {
      console.error('Error loading related posts:', error);
      setRelatedPosts([]);
    } finally {
      setLoadingRelated(false);
    }
  };

  useEffect(() => {
    let isMounted = true;
    let fetchTimeout: NodeJS.Timeout;

    const fetchPost = async () => {
      // Kiểm tra xem có request đang chạy không
      if (fetchingRef.current) {
        return;
      }

      try {
        fetchingRef.current = true;
        setLoading(true);

        const response = await forumApi.getPost(slug);

        if (!isMounted) return; // Kiểm tra component còn mount không

        if (!response.data) {
          throw new Error('Không tìm thấy bài viết');
        }

        const postData = response.data;
        const currentUserId = user?._id;


        // Kiểm tra quyền xem bài viết
        if (postData.visibility === 'private') {
          // Nếu không phải người đăng bài
          if (!user || postData.userId._id !== currentUserId) {
            toast.error('Bạn không có quyền xem bài viết này');
            // navigate('/forum'); // Tạm thời disable
            return;
          }
        }

        // Kiểm tra xem đã tăng view cho post này chưa
        if (!viewedPostsRef.current.has(postData._id)) {
          viewedPostsRef.current.add(postData._id);
        }

        setPost(postData.post);

        setIsLiked(postData.post.likes?.includes(user?._id) || false);
        setIsBookmarked(postData.post.savedBy?.includes(user?._id) || false);
        setLikeCount(postData.post.likes?.length);
        setSaveCount(postData.post.savedBy?.length);
        setCommentCount(postData.post.commentCount);
        setViewCount(postData.post.viewCount);

        // Load related posts
        if (postData.post) {
          loadRelatedPosts(postData.post);
        }

        // Kiểm tra follow status và lấy thông tin follow
        //  if (postData.userId) {
        //    try {
        //      // Load author stats từ API (includes updated level)
        //      const authorId = postData.userId._id || postData.userId;
        //      const publicStats = await userApi.getUserPublicStats(authorId);

        //      // Update author object with latest level data
        //      if (publicStats.level !== undefined && postData.userId) {
        //        postData.userId.level = publicStats.level;
        //        if (publicStats.levelTitle !== undefined) {
        //          postData.userId.levelTitle = publicStats.levelTitle;
        //        }
        //        // Update post state to reflect new level
        //        setPost({ ...postData });
        //      }

        //      setAuthorStats({
        //        documentsCount: publicStats.documentsCount ?? 0,
        //        postsCount: publicStats.postsCount ?? 0,
        //        points: publicStats.points ?? 0,
        //        followersCount: publicStats.followersCount ?? 0,
        //      });

        //      // Lấy followers
        //     //  const followersResponse = await api.get(`/users/${authorId}/followers`);
        //     //  const followers = followersResponse.data.followers || [];
        //     //  const actualFollowersCount = publicStats.followersCount ?? followers.length;
        //     //  setFollowersCount(actualFollowersCount);

        //      // Kiểm tra currentUser có follow author không
        //     //  if (currentUser && authorId !== currentUser._id) {
        //     //    setIsFollowing(followers.some((follower: any) => follower._id === currentUser._id));
        //     //  }
        //    } catch (error) {
        //      console.error('Error loading author stats:', error);
        //      // Fallback nếu không load được stats
        //      setAuthorStats({
        //        documentsCount: postData.userId.stats?.documentsCount || 0,
        //        postsCount: postData.userId.stats?.postsCount || 0,
        //        points: postData.userId.points || 0,
        //        followersCount: 0,
        //      });
        //    }

        //    // Load related posts
        //    loadRelatedPosts(postData);
        //  }
      } catch (error) {
        console.error('Error fetching post:', error);
        toast.error('Không thể tải bài viết');
      } finally {
        if (isMounted) {
          setLoading(false);
        }
        fetchingRef.current = false;
      }
    };

    // Debounce fetch để tránh gọi nhiều lần
    fetchTimeout = setTimeout(fetchPost, 100);

    return () => {
      isMounted = false;
      if (fetchTimeout) {
        clearTimeout(fetchTimeout);
      }
      fetchingRef.current = false;
    };
  }, [slug]); // Chỉ phụ thuộc vào slug, không phụ thuộc vào currentUser?._id

  useEffect(() => {
    hasScrolledToCommentRef.current = false;
  }, [slug]);

  // Scroll to comment when hash is present in URL
  useEffect(() => {
    if (!post || loading || hasScrolledToCommentRef.current) {
      return;
    }

    const hash = window.location.hash;
    if (!hash || !hash.startsWith('#comment-')) {
      return;
    }

    const commentId = hash.replace('#comment-', '');
    let attempts = 0;
    let timeoutId: ReturnType<typeof setTimeout> | null = null;

    const highlightComment = (element: HTMLElement) => {
      const previousTransition = element.style.transition;
      const previousBackground = element.style.backgroundColor;

      element.style.transition = previousTransition || 'background-color 0.3s ease';
      element.style.backgroundColor = 'rgba(59, 130, 246, 0.12)';

      setTimeout(() => {
        element.style.backgroundColor = previousBackground;
        element.style.transition = previousTransition;
      }, 2000);
    };

    const tryScroll = () => {
      const commentElement = document.getElementById(`comment-${commentId}`);
      if (commentElement) {
        commentElement.scrollIntoView({ behavior: 'smooth', block: 'center' });
        highlightComment(commentElement as HTMLElement);
        hasScrolledToCommentRef.current = true;
        return;
      }

      if (attempts < 10) {
        attempts += 1;
        timeoutId = setTimeout(tryScroll, 250);
      }
    };

    tryScroll();

    return () => {
      if (timeoutId) {
        clearTimeout(timeoutId);
      }
    };
  }, [post, loading, commentCount]);

  const handleLike = async () => {

    try {
      // Optimistic update - cập nhật UI ngay lập tức
      const newIsLiked = !isLiked;
      const newLikeCount = newIsLiked ? likeCount + 1 : Math.max(0, likeCount - 1);

      setIsLiked(newIsLiked);
      setLikeCount(newLikeCount);

      let response;
      if (isLiked) {
        response = await forumApi.unlikePost(post._id);
      } else {
        response = await forumApi.likePost(post._id);
      }

      if (response.data && response.data.success) {
        // Cập nhật với dữ liệu thật từ server nếu có
        if (response.data.likeCount !== undefined) {
          setLikeCount(response.data.likeCount);
        }
        // Đảm bảo trạng thái like đúng
        setIsLiked(response.data.liked);
      } else {
        // Rollback nếu API thất bại
        setIsLiked(isLiked);
        setLikeCount(likeCount);
        toast.error('Có lỗi khi thích bài viết');
      }
    } catch (error) {
      // Rollback nếu có lỗi
      setIsLiked(isLiked);
      setLikeCount(likeCount);
      console.error('Like error:', error);
      toast.error('Có lỗi khi thích bài viết');
    }
  };

  const handleFollow = async () => {
    const currentUser = getCurrentUser();
    if (!currentUser) {
      toast.error('Vui lòng đăng nhập để theo dõi');
      return;
    }

    if (!author) {
      toast.error('Không tìm thấy thông tin tác giả');
      return;
    }

    // try {
    //   // Optimistic update
    //   const newIsFollowing = !isFollowing;
    //   const newFollowersCount = newIsFollowing ? followersCount + 1 : Math.max(0, followersCount - 1);

    //   setIsFollowing(newIsFollowing);
    //   setFollowersCount(newFollowersCount);

    //   let response;
    //   if (isFollowing) {
    //     // Unfollow
    //     response = await api.delete(`/users/${author._id}/follow`);
    //   } else {
    //     // Follow
    //     response = await api.post(`/users/${author._id}/follow`);
    //   }

    //   if (response.status === 200 || response.status === 201) {
    //     const data = response.data;
    //     toast.success(data.message || (isFollowing ? 'Đã hủy theo dõi' : 'Đã theo dõi'));
    //   } else {
    //     // Rollback nếu API thất bại
    //     setIsFollowing(isFollowing);
    //     setFollowersCount(followersCount);
    //     const errorData = response.data;
    //     toast.error(errorData.error || 'Có lỗi khi thực hiện thao tác');
    //   }
    // } catch (error) {
    //   // Rollback nếu có lỗi
    //   setIsFollowing(isFollowing);
    //   setFollowersCount(followersCount);
    //   console.error('Follow error:', error);
    //   toast.error('Có lỗi khi thực hiện thao tác');
    // }
  };

  const handleBookmark = async () => {

    try {
      // Optimistic update - cập nhật UI ngay lập tức
      const newIsBookmarked = !isBookmarked;
      const newSaveCount = newIsBookmarked ? saveCount + 1 : Math.max(0, saveCount - 1);

      setIsBookmarked(newIsBookmarked);
      setSaveCount(newSaveCount);

      let response;
      if (isBookmarked) {
        response = await forumApi.unsavePost(post._id);
      } else {
        response = await forumApi.savePost(post._id);
      }

      if (response.data && response.data.success) {
        // Cập nhật với dữ liệu thật từ server nếu có
        if (response.data.saveCount !== undefined) {
          setSaveCount(response.data.saveCount);
        }
        // Đảm bảo trạng thái bookmark đúng
        setIsBookmarked(response.data.saved);
      } else {
        // Rollback nếu API thất bại
        setIsBookmarked(isBookmarked);
        setSaveCount(saveCount);
        toast.error('Có lỗi khi lưu bài viết');
      }
    } catch (error) {
      // Rollback nếu có lỗi
      setIsBookmarked(isBookmarked);
      setSaveCount(saveCount);
      console.error('Bookmark error:', error);
      toast.error('Có lỗi khi lưu bài viết');
    }
  };

  const handleCommentCountChange = (newCount: number) => {
    setCommentCount(newCount);
  };

  const handleShare = () => {
    if (navigator.share) {
      navigator.share({
        title: post.title,
        text: post.content.substring(0, 100) + '...',
        url: window.location.href
      }).catch(error => {
        console.error('Error sharing:', error);
      });
    } else {
      // Fallback: Copy link to clipboard
      navigator.clipboard.writeText(window.location.href).then(() => {
        toast.success('Đã sao chép link bài viết');
      }).catch(error => {
        console.error('Error copying to clipboard:', error);
        toast.error('Không thể sao chép link');
      });
    }
  };


  const handleCancelEdit = () => {
    setIsEditing(false);
  };

  // Hàm sinh slug khi sửa title
  const handleEditTitleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const value = e.target.value;
    setEditTitle(value);
    const slugValue = value
      .replace(/đ/g, 'd')
      .replace(/Đ/g, 'D')
      .normalize('NFD')
      .replace(/[\u0300-\u036f]/g, '')
      .toLowerCase()
      .replace(/[^a-z0-9\s-]/g, '')
      .replace(/\s+/g, '-')
      .replace(/-+/g, '-')
      .replace(/^-+|-+$/g, '');
    setEditSlug(slugValue);
  };

  // Xử lý lưu bài viết đã sửa
  const handleSaveEdit = async () => {
    try {
      const formData = new FormData();
      formData.append('title', editTitle);
      formData.append('slug', editSlug);
      formData.append('summary', editSummary);
      formData.append('subject', editSubject);
      formData.append('tags', JSON.stringify(editTags));
      formData.append('content', editContent);
      if (editCoverImage) formData.append('coverImage', editCoverImage);
      await forumApi.updatePost(post._id, formData);
      setPost({ ...post, title: editTitle, slug: editSlug, summary: editSummary, subject: editSubject, tags: editTags, content: editContent, imageUrl: editCoverImage ? URL.createObjectURL(editCoverImage) : post.imageUrl });
      setIsEditing(false);
      toast.success('Cập nhật bài viết thành công');
    } catch (error) {
      toast.error('Cập nhật thất bại');
    }
  };

  // Xử lý xóa bài viết
  const handleDelete = () => {
    setShowDeleteConfirm(true);
  };

  const confirmDelete = async () => {
    try {
      await forumApi.deletePost(post._id);
      toast.success('Đã xóa bài viết');
      router.push('/forum');
    } catch (error) {
      toast.error('Xóa bài viết thất bại');
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background">
        <div className="text-center">
          <div className="animate-spin h-8 w-8 border-4 border-primary border-t-transparent rounded-full mx-auto" />
          <p className="mt-3 text-muted-foreground text-sm font-medium">Đang tải…</p>
        </div>
      </div>
    );
  }

  if (!post) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background p-6">
        <div className="text-center max-w-md bg-card border border-border rounded-3xl p-8 shadow-sm">
          <div className="text-4xl mb-3">⚠️</div>
          <h2 className="text-base font-bold text-foreground mb-2">Không tìm thấy bài viết</h2>
          <p className="text-xs text-muted-foreground mb-6">Bài viết này có thể đã bị xóa hoặc không tồn tại.</p>
          <Link href="/forum" className="cursor-pointer inline-flex items-center gap-2 px-5 py-2.5 rounded-xl bg-primary text-white text-xs font-bold shadow-md hover:bg-primary/95 transition-all focus-visible:ring-2 focus-visible:ring-primary/50 outline-hidden">
            Quay lại diễn đàn
          </Link>
        </div>
      </div>
    );
  }

  const author = post.userId;
  const avatarUrl = author?.avatarUrl || '/unknown-avatar.jpg';
  const authorName = author?.name || author?.username || 'User';
  let postTime = 'Không xác định';
  if (post.createdAt && !isNaN(new Date(post.createdAt).getTime())) {
    postTime = formatDistanceToNow(new Date(post.createdAt), { addSuffix: true, locale: vi });
  }

  return (
    <div className="min-h-screen bg-background text-foreground pb-20">
      {/* ── Top bar ──────────────────────────────────────────────────── */}
      <div className="sticky top-16 z-40 bg-background/90 backdrop-blur-md border-b border-border px-6 py-3.5 flex items-center justify-between gap-4">
        <button
          onClick={() => router.back()}
          aria-label="Quay lại trang trước"
          className="inline-flex items-center gap-2 text-sm font-bold text-foreground hover:text-primary transition-colors focus-visible:ring-2 focus-visible:ring-primary/50 outline-hidden rounded-md px-2 py-1 cursor-pointer"
        >
          <FiArrowLeft size={16} />
          Quay lại
        </button>

        <div className="flex items-center gap-2">
          {user && author && user._id === author._id && !isEditing ? (
            <>
              <button
                className="cursor-pointer inline-flex items-center gap-1.5 px-4 py-2 rounded-xl border border-blue-500/35 bg-blue-500/10 text-blue-600 dark:text-blue-400 text-xs font-bold hover:bg-blue-500/20 transition-all focus-visible:ring-2 focus-visible:ring-blue-500/50 outline-hidden"
                onClick={() => router.push(`/forum/edit/${post.slug}`)}
              >
                Chỉnh sửa
              </button>
              <button
                className="cursor-pointer inline-flex items-center gap-1.5 px-4 py-2 rounded-xl border border-rose-500/35 bg-rose-500/10 text-rose-600 dark:text-rose-400 text-xs font-bold hover:bg-rose-500/20 transition-all focus-visible:ring-2 focus-visible:ring-rose-500/50 outline-hidden"
                onClick={handleDelete}
              >
                Xóa bài
              </button>
            </>
          ) : null}
        </div>
      </div>

      {/* ── Main layout: 2 columns ───────────────────────────────────── */}
      <div className="max-w-7xl mx-auto px-6 py-8">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">

          {/* LEFT COLUMN: Main Post Content / Editor, Action Bar */}
          <div className="lg:col-span-2 space-y-6">

            <div className="bg-card border border-border rounded-3xl p-6 md:p-8 shadow-xs relative">

              {/* Cover Image */}
              {post.imageUrl ? (
                <div className="relative aspect-[21/9] w-full overflow-hidden rounded-2xl bg-muted mb-6 shadow-xs">
                  <img
                    src={post.imageUrl}
                    alt={post.title || 'Ảnh bài viết'}
                    width={800}
                    height={343}
                    className="object-cover w-full h-full"
                  />
                </div>
              ) : null}

              {/* Editor mode */}
              {isEditing ? (
                <div className="space-y-6">
                  <div className="space-y-1.5">
                    <label className="text-xs font-extrabold uppercase tracking-wider text-muted-foreground">Tiêu đề *</label>
                    <input
                      className="w-full rounded-xl border border-border bg-background px-4 py-2.5 text-sm text-foreground outline-hidden focus-visible:ring-2 focus-visible:ring-primary/50 focus-visible:ring-offset-2 transition-all"
                      value={editTitle}
                      onChange={handleEditTitleChange}
                      required
                    />
                  </div>
                  <div className="space-y-1.5">
                    <label className="text-xs font-extrabold uppercase tracking-wider text-muted-foreground">Slug</label>
                    <input
                      className="w-full rounded-xl border border-border bg-muted/40 px-4 py-2.5 text-sm text-muted-foreground cursor-not-allowed outline-hidden"
                      value={editSlug}
                      readOnly
                    />
                  </div>
                  <div className="space-y-1.5">
                    <label className="text-xs font-extrabold uppercase tracking-wider text-muted-foreground">Mô tả ngắn</label>
                    <textarea
                      className="w-full rounded-xl border border-border bg-background px-4 py-2.5 text-sm text-foreground outline-hidden focus-visible:ring-2 focus-visible:ring-primary/50 focus-visible:ring-offset-2 transition-all"
                      value={editSummary}
                      onChange={e => setEditSummary(e.target.value)}
                      rows={3}
                    />
                  </div>
                  <div className="space-y-1.5">
                    <label className="text-xs font-extrabold uppercase tracking-wider text-muted-foreground">Chủ đề</label>
                    <input
                      className="w-full rounded-xl border border-border bg-background px-4 py-2.5 text-sm text-foreground outline-hidden focus-visible:ring-2 focus-visible:ring-primary/50 focus-visible:ring-offset-2 transition-all"
                      value={editSubject}
                      onChange={e => setEditSubject(e.target.value)}
                    />
                  </div>
                  <div className="space-y-1.5">
                    <label className="text-xs font-extrabold uppercase tracking-wider text-muted-foreground">Tags (phân cách bởi dấu phẩy)</label>
                    <input
                      className="w-full rounded-xl border border-border bg-background px-4 py-2.5 text-sm text-foreground outline-hidden focus-visible:ring-2 focus-visible:ring-primary/50 focus-visible:ring-offset-2 transition-all"
                      value={editTags.join(', ')}
                      onChange={e => setEditTags(e.target.value.split(',').map(t => t.trim()).filter(Boolean))}
                    />
                  </div>
                  <div className="space-y-2">
                    <label className="text-xs font-extrabold uppercase tracking-wider text-muted-foreground">Ảnh chủ đề</label>
                    <input
                      type="file"
                      accept="image/*"
                      onChange={e => setEditCoverImage(e.target.files && e.target.files[0] ? e.target.files[0] : null)}
                      className="w-full rounded-xl border border-border bg-background px-4 py-2 text-sm text-foreground focus-visible:ring-2 focus-visible:ring-primary/50 outline-hidden file:mr-4 file:py-1 file:px-3 file:rounded-full file:border-0 file:text-xs file:font-semibold file:bg-primary/10 file:text-primary hover:file:bg-primary/20"
                      aria-label="Chọn ảnh chủ đề"
                      title="Chọn ảnh chủ đề"
                    />
                    {editCoverImage ? (
                      <img src={URL.createObjectURL(editCoverImage)} alt="cover" className="max-w-[200px] mt-2 rounded-xl border border-border" />
                    ) : post.imageUrl ? (
                      <img src={post.imageUrl} alt={post.title || 'Ảnh chủ đề'} className="max-w-[200px] mt-2 rounded-xl border border-border" />
                    ) : null}
                  </div>
                  <div className="space-y-1.5">
                    <label className="text-xs font-extrabold uppercase tracking-wider text-muted-foreground">Nội dung bài viết</label>
                    <RichTextEditor
                      value={editContent}
                      onChange={setEditContent}
                      placeholder="Nhập nội dung bài viết…"
                      style={{ minHeight: 200, maxHeight: 500, overflowY: 'auto', lineHeight: '1.6', position: 'relative', border: '1px solid #e5e7eb', borderRadius: 8, padding: 12, background: '#fff' }}
                    />
                  </div>
                  <div className="flex items-center gap-2.5 pt-4">
                    <button className="cursor-pointer px-5 py-2.5 rounded-xl bg-primary text-white font-bold text-sm shadow-md hover:bg-primary/95 focus-visible:ring-2 focus-visible:ring-primary/50 focus-visible:ring-offset-2 outline-hidden" onClick={handleSaveEdit} type="button">Lưu lại</button>
                    <button className="cursor-pointer px-5 py-2.5 rounded-xl border border-border bg-card text-foreground font-bold text-sm hover:bg-muted focus-visible:ring-2 focus-visible:ring-primary/50 focus-visible:ring-offset-2 outline-hidden" onClick={handleCancelEdit} type="button">Hủy bỏ</button>
                  </div>
                </div>
              ) : (
                <div className="space-y-4">
                  {/* Category & Visibility Badge */}
                  <div className="flex items-center gap-2 flex-wrap text-xs font-bold">
                    {post.subject ? (
                      <span className="px-3 py-1 rounded-full bg-primary/10 text-primary border border-primary/20 uppercase tracking-wider">
                        {getCategoryName(post.subject)}
                      </span>
                    ) : null}
                    <span className={`px-3 py-1 rounded-full border ${post.visibility === 'private' ? 'bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/20' : 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/20'}`}>
                      {post.visibility === 'private' ? '🔒 Riêng tư' : '🌐 Công khai'}
                    </span>
                  </div>

                  {/* Title */}
                  <h1 className="text-2xl md:text-3xl font-extrabold text-foreground leading-tight">{post.title}</h1>

                  {/* Date & Views */}
                  <div className="flex items-center gap-4 text-xs font-semibold text-muted-foreground border-b border-border pb-4">
                    <span>Đăng {postTime}</span>
                    <span>•</span>
                    <span>{viewCount} lượt xem</span>
                  </div>

                  {/* Content HTML */}
                  <section className="text-sm md:text-base leading-relaxed text-foreground/90 whitespace-normal prose dark:prose-invert max-w-none pt-2">
                    <div
                      className="forum-post-detail-html-content"
                      dangerouslySetInnerHTML={{
                        __html: (() => {
                          if (!post?.content) return '';
                          let content = String(post.content);

                          // Xử lý URL Giphy dạng text - convert thành thẻ <img>
                          const giphyUrlPattern = /https?:\/\/(?:media\d?\.)?giphy\.com\/media\/[^\s<>"'\)\]&]+/gi;
                          const giphyUrls = content.match(giphyUrlPattern);

                          if (giphyUrls && giphyUrls.length > 0) {
                            const uniqueUrls = [...new Set(giphyUrls)].sort((a, b) => b.length - a.length);

                            uniqueUrls.forEach((url: string) => {
                              const cleanUrl = url.trim();

                              // Bỏ qua nếu URL đã nằm trong thẻ <img> src
                              const escaped = cleanUrl.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
                              if (new RegExp(`<img[^>]+src=["']${escaped}`, 'i').test(content)) {
                                return;
                              }

                              const imgTag = `<img src="${cleanUrl}" alt="sticker" width="150" height="150" style="max-width: 150px; max-height: 150px; border-radius: 8px; margin: 8px 0; display: block;" />`;

                              // Replace URL trong content (tránh replace trong HTML attributes)
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
                    />
                  </section>

                  {/* Tags */}
                  {(() => {
                    let tagsArray = post.tags;
                    if (typeof post.tags === 'string') {
                      try { tagsArray = JSON.parse(post.tags); } catch { tagsArray = [post.tags]; }
                    }
                    if (!Array.isArray(tagsArray)) tagsArray = [];

                    return tagsArray.length > 0 ? (
                      <div className="flex flex-wrap gap-1.5 pt-4 border-t border-border mt-6">
                        {tagsArray.map((tag: string, index: number) => (
                          <Link
                            key={index}
                            href={`/forum?tag=${encodeURIComponent(typeof tag === 'string' ? tag : String(tag))}`}
                            className="px-3 py-1 bg-muted hover:bg-primary hover:text-white transition-all text-xs font-semibold text-muted-foreground rounded-full"
                          >
                            #{typeof tag === 'string' ? tag : String(tag)}
                          </Link>
                        ))}
                      </div>
                    ) : null;
                  })()}

                </div>
              )}
            </div>

            {/* Action buttons below card */}
            {!isEditing ? (
              <div className="flex items-center gap-2 flex-wrap">
                <button
                  onClick={handleLike}
                  aria-label={isLiked ? 'Bỏ thích bài viết này' : 'Thích bài viết này'}
                  className={`cursor-pointer inline-flex items-center gap-1.5 px-5 py-3 rounded-2xl border text-xs font-bold transition-all duration-200 focus-visible:ring-2 focus-visible:ring-rose-500/50 outline-hidden ${isLiked
                    ? 'border-rose-500 bg-rose-500/10 text-rose-500 font-extrabold'
                    : 'border-border bg-card text-foreground hover:bg-muted'
                    }`}
                >
                  <FaHeart className={isLiked ? 'text-rose-500' : ''} />
                  <span>Thích ({likeCount})</span>
                </button>
                <button
                  onClick={handleBookmark}
                  aria-label={isBookmarked ? 'Bỏ lưu bài viết này' : 'Lưu bài viết này'}
                  className={`cursor-pointer inline-flex items-center gap-1.5 px-5 py-3 rounded-2xl border text-xs font-bold transition-all duration-200 focus-visible:ring-2 focus-visible:ring-amber-500/50 outline-hidden ${isBookmarked
                    ? 'border-amber-500 bg-amber-500/10 text-amber-500 font-extrabold'
                    : 'border-border bg-card text-foreground hover:bg-muted'
                    }`}
                >
                  <FaBookmark className={isBookmarked ? 'text-amber-500' : ''} />
                  <span>Lưu lại ({saveCount})</span>
                </button>
                <button
                  onClick={handleShare}
                  aria-label="Chia sẻ liên kết đến bài viết này"
                  className="cursor-pointer inline-flex items-center gap-1.5 px-5 py-3 rounded-2xl border border-border bg-card text-xs font-bold text-foreground hover:bg-muted transition-all focus-visible:ring-2 focus-visible:ring-primary/50 outline-hidden"
                >
                  Chia sẻ
                </button>
                <ReportButton
                  itemId={post._id}
                  itemType="post"
                  className="px-5 py-3 text-xs font-bold cursor-pointer rounded-2xl border border-border bg-card text-muted-foreground hover:text-foreground"
                />
              </div>
            ) : null}

          </div>

          {/* RIGHT COLUMN: Sidebar (Author stats, related posts) */}
          <div className="lg:col-span-1">
            <div className="lg:sticky lg:top-24 space-y-6">

              {/* Author Widget Card */}
              <div className="bg-card border border-border rounded-3xl p-6 shadow-sm text-center space-y-4">

                {/* Header info */}
                <div className="space-y-3">
                  <div className="relative inline-block">
                    <div className="block focus-visible:ring-4 focus-visible:ring-primary/20 outline-hidden rounded-full">
                      <img
                        src={avatarUrl}
                        alt={authorName}
                        width={80}
                        height={80}
                        className="h-20 w-20 rounded-full mx-auto object-cover border-3 border-primary/20 bg-muted hover:scale-102 transition-transform duration-300"
                      />
                    </div>
                  </div>

                  <div className="space-y-1">
                    <div className="hover:text-primary transition-colors focus-visible:ring-2 focus-visible:ring-primary/50 outline-hidden rounded-sm px-1.5 py-0.5">
                      <h3 className="author-name font-bold text-base text-foreground leading-snug">{authorName}</h3>
                    </div>
                    {/* <div className="flex items-center justify-center gap-1.5 text-xs text-muted-foreground font-semibold">
                      <span className="px-2 py-0.5 rounded-sm bg-primary/10 text-primary font-bold">Level {author?.level || 1}</span>
                      <span>•</span>
                      <span>{author?.levelTitle || 'Mới tham gia'}</span>
                    </div> */}
                  </div>


                </div>

                {/* Stats widget grid */}
                {/* <div className="grid grid-cols-2 gap-px bg-border/50 rounded-2xl border border-border/50 overflow-hidden text-xs">
                  <div className="bg-card p-3 flex flex-col items-center justify-center">
                    <span className="font-extrabold text-base text-foreground">{authorStats?.points ?? author?.points ?? 0}</span>
                    <span className="text-[10px] text-muted-foreground font-medium uppercase tracking-wider">Điểm</span>
                  </div>
                  <div className="bg-card p-3 flex flex-col items-center justify-center">
                    <span className="font-extrabold text-base text-foreground">{authorStats?.documentsCount ?? author?.stats?.documentsCount ?? 0}</span>
                    <span className="text-[10px] text-muted-foreground font-medium uppercase tracking-wider">Tài liệu</span>
                  </div>
                  <div className="bg-card p-3 flex flex-col items-center justify-center">
                    <span className="font-extrabold text-base text-foreground">{authorStats?.followersCount ?? followersCount}</span>
                    <span className="text-[10px] text-muted-foreground font-medium uppercase tracking-wider">Theo dõi</span>
                  </div>
                  <div className="bg-card p-3 flex flex-col items-center justify-center">
                    <span className="font-extrabold text-base text-foreground">{authorStats?.postsCount ?? author?.stats?.postsCount ?? 0}</span>
                    <span className="text-[10px] text-muted-foreground font-medium uppercase tracking-wider">Bài viết</span>
                  </div>
                </div> */}
                {/* Social interaction buttons */}
                {(() => {
                  const isOwnPost = user && author && user._id === author._id;
                  if (isOwnPost) return null;

                  return (
                    <div className="flex items-center gap-2 pt-2">
                      {/* <button className="flex-1 cursor-pointer inline-flex items-center justify-center px-4 py-2.5 rounded-xl bg-primary text-white font-bold text-xs shadow-md hover:bg-primary/95 transition-all focus-visible:ring-2 focus-visible:ring-primary/50 outline-hidden" onClick={handleFollow}>
                        {isFollowing ? 'Đang theo dõi' : 'Theo dõi'}
                      </button> */}
                      <button
                        className="flex-1 cursor-pointer inline-flex items-center justify-center gap-1.5 px-4 py-2.5 rounded-xl border border-border bg-card text-foreground font-bold text-xs hover:bg-muted transition-all focus-visible:ring-2 focus-visible:ring-primary/50 outline-hidden"
                        onClick={() => {
                          const currentUser = getCurrentUser();
                          if (!currentUser) {
                            toast.error('Vui lòng đăng nhập để gửi tin nhắn!');
                            return;
                          }
                          if (author && author._id) {
                            openChat(author._id, {
                              username: author.username,
                              avatarUrl: author.avatarUrl,
                            });
                          } else {
                            toast.error('Không tìm thấy thông tin tác giả');
                          }
                        }}
                      >
                        <FiMessageSquare size={13} />
                        <span>Nhắn tin</span>
                      </button>
                    </div>
                  );
                })()}

              </div>

              {/* Related Posts Card */}
              <div className="bg-card border border-border rounded-3xl p-6 shadow-sm space-y-4">
                <h3 className="text-xs font-extrabold text-muted-foreground uppercase tracking-wider border-b border-border pb-2.5">Bài viết liên quan</h3>

                {loadingRelated ? (
                  <div className="flex items-center justify-center gap-2 py-6 text-muted-foreground text-sm font-semibold">
                    <div className="animate-spin h-4 w-4 border-2 border-primary border-t-transparent rounded-full" />
                    <span>Đang tải…</span>
                  </div>
                ) : relatedPosts.length > 0 ? (
                  <div className="space-y-3.5">
                    {relatedPosts.map((relatedPost) => {
                      const postSlug = relatedPost.slug || relatedPost._id;
                      const postAuthor = relatedPost.userId?.name || relatedPost.userId?.username || 'User';
                      const postTime = relatedPost.createdAt
                        ? formatDistanceToNow(new Date(relatedPost.createdAt), { addSuffix: true, locale: vi })
                        : '';
                      const thumbnail = relatedPost.imageUrl
                        || relatedPost.coverImage
                        || relatedPost.thumbnail
                        || (relatedPost.images && relatedPost.images.length > 0 ? relatedPost.images[0] : null)
                        || '/unknown-avatar.jpg';

                      return (
                        <Link
                          href={`/forum/${postSlug}`}
                          key={relatedPost._id}
                          className="group flex items-start gap-3 p-1.5 rounded-xl hover:bg-muted/50 transition-all duration-200 outline-hidden focus-visible:ring-2 focus-visible:ring-primary/30"
                        >
                          <div className="related-post-thumbnail shrink-0 w-16 h-12 rounded-lg overflow-hidden bg-muted">
                            <img
                              src={thumbnail}
                              alt={relatedPost.title}
                              width={64}
                              height={48}
                              className="w-full h-full object-cover transition-transform duration-300 group-hover:scale-105"
                              onError={(e) => {
                                const target = e.target as HTMLImageElement;
                                target.src = '/unknown-avatar.jpg';
                              }}
                            />
                          </div>
                          <div className="flex flex-col gap-1 min-w-0 flex-1">
                            <h4 className="font-bold text-xs text-foreground group-hover:text-primary transition-colors leading-snug line-clamp-2">
                              {relatedPost.title}
                            </h4>
                            <div className="flex items-center gap-1.5 text-[10px] text-muted-foreground font-semibold">
                              <span className="truncate max-w-[80px]">{postAuthor}</span>
                              {postTime ? <span>• {postTime}</span> : null}
                            </div>
                          </div>
                        </Link>
                      );
                    })}
                  </div>
                ) : (
                  <div className="text-center py-6 text-xs text-muted-foreground font-medium italic">
                    Chưa có bài viết liên quan
                  </div>
                )}
              </div>

            </div>
          </div>

        </div>

        {/* BOTTOM SECTION: Comments */}
        <section className="mt-12 pt-8 border-t border-border">
          <div className="max-w-4xl">
            <h3 className="text-lg font-extrabold text-foreground mb-6">Bình luận & Thảo luận ({commentCount})</h3>
            <CommentList
              targetId={post._id}
              onCommentCountChange={handleCommentCountChange}
              commentApi={forumApi}
            />
          </div>
        </section>

      </div>

      {/* Delete Confirmation Dialog */}
      <ConfirmDialog
        isOpen={showDeleteConfirm}
        title="Xóa bài viết"
        message="Bạn có chắc chắn muốn xóa bài viết này? Hành động này không thể hoàn tác."
        confirmText="Xóa"
        cancelText="Hủy"
        type="danger"
        onConfirm={confirmDelete}
        onCancel={() => setShowDeleteConfirm(false)}
      />
    </div>
  );
};

export default ForumPostDetail; 