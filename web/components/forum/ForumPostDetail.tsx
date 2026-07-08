/* eslint-disable @typescript-eslint/no-explicit-any */
import React, { useState, useEffect } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { useChatModal } from '@/store/chatstore';
import { FaHeart, FaBookmark } from 'react-icons/fa';
import { FiArrowLeft, FiMessageSquare } from 'react-icons/fi';
import { forumApi } from '../../lib/forumApi';
import * as userApi from '../../services/user.service';
import formatDistanceToNow from 'date-fns/formatDistanceToNow';
import vi from 'date-fns/locale/vi';
import { toast } from 'react-toastify';
import Loader from './ui/Loader';
import ReportButton from './ui/ReportButton';
import CommentList from './ui/CommentList';
import api from '../../lib/api-client';
// import styled from 'styled-components';
import '../../styles/pages/forum/ForumPostDetail.css';
import { ConfirmDialog } from './ui/ConfirmDialog';
import RichTextEditor from './ui/RichTextEditor';

const ForumPostDetail: React.FC = () => {
  const { slug } = useParams<{ slug: string }>();
  const navigate = useNavigate();
  const { openChat } = useChatModal();
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

  if (!slug) {
    return <div style={{ padding: 32, textAlign: 'center', color: '#ef4444', fontWeight: 600 }}>Không tìm thấy bài viết hoặc đường dẫn không hợp lệ.</div>;
  }

  // Helper function to get current user
  const getCurrentUser = () => {
    const userStr = localStorage.getItem('user');
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
        const currentUserId = localStorage.getItem('userId');
        const currentUser = getCurrentUser();

        // Kiểm tra quyền xem bài viết
        if (postData.visibility === 'private') {
          // Nếu không phải người đăng bài
          if (!currentUserId || postData.userId._id !== currentUserId) {
            toast.error('Bạn không có quyền xem bài viết này');
            // navigate('/forum'); // Tạm thời disable
            return;
          }
        }

        // Kiểm tra xem đã tăng view cho post này chưa
        if (!viewedPostsRef.current.has(postData._id)) {
          viewedPostsRef.current.add(postData._id);
        }

        setPost(postData);
        setIsLiked(postData.likes?.includes(currentUser?._id) || false);
        setIsBookmarked(postData.savedBy?.includes(currentUser?._id) || false);
        setLikeCount(postData.likes?.length || 0);
        setSaveCount(postData.savedBy?.length || 0);
        setCommentCount(postData.comments?.length || 0);
        setViewCount(postData.viewCount || 0);

        // Kiểm tra follow status và lấy thông tin follow
        if (postData.userId) {
          try {
            // Load author stats từ API (includes updated level)
            const authorId = postData.userId._id || postData.userId;
            const publicStats = await userApi.getUserPublicStats(authorId);

            // Update author object with latest level data
            if (publicStats.level !== undefined && postData.userId) {
              postData.userId.level = publicStats.level;
              if (publicStats.levelTitle !== undefined) {
                postData.userId.levelTitle = publicStats.levelTitle;
              }
              // Update post state to reflect new level
              setPost({ ...postData });
            }

            setAuthorStats({
              documentsCount: publicStats.documentsCount ?? 0,
              postsCount: publicStats.postsCount ?? 0,
              points: publicStats.points ?? 0,
              followersCount: publicStats.followersCount ?? 0,
            });

            // Lấy followers
            const followersResponse = await api.get(`/users/${authorId}/followers`);
            const followers = followersResponse.data.followers || [];
            const actualFollowersCount = publicStats.followersCount ?? followers.length;
            setFollowersCount(actualFollowersCount);

            // Kiểm tra currentUser có follow author không
            if (currentUser && authorId !== currentUser._id) {
              setIsFollowing(followers.some((follower: any) => follower._id === currentUser._id));
            }
          } catch (error) {
            console.error('Error loading author stats:', error);
            // Fallback nếu không load được stats
            setAuthorStats({
              documentsCount: postData.userId.stats?.documentsCount || 0,
              postsCount: postData.userId.stats?.postsCount || 0,
              points: postData.userId.points || 0,
              followersCount: 0,
            });
          }

          // Load related posts
          loadRelatedPosts(postData);
        }
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
    const currentUser = getCurrentUser();
    if (!currentUser) {
      toast.error('Vui lòng đăng nhập để thích bài viết');
      return;
    }

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

    try {
      // Optimistic update
      const newIsFollowing = !isFollowing;
      const newFollowersCount = newIsFollowing ? followersCount + 1 : Math.max(0, followersCount - 1);

      setIsFollowing(newIsFollowing);
      setFollowersCount(newFollowersCount);

      let response;
      if (isFollowing) {
        // Unfollow
        response = await api.delete(`/users/${author._id}/follow`);
      } else {
        // Follow
        response = await api.post(`/users/${author._id}/follow`);
      }

      if (response.status === 200 || response.status === 201) {
        const data = response.data;
        toast.success(data.message || (isFollowing ? 'Đã hủy theo dõi' : 'Đã theo dõi'));
      } else {
        // Rollback nếu API thất bại
        setIsFollowing(isFollowing);
        setFollowersCount(followersCount);
        const errorData = response.data;
        toast.error(errorData.error || 'Có lỗi khi thực hiện thao tác');
      }
    } catch (error) {
      // Rollback nếu có lỗi
      setIsFollowing(isFollowing);
      setFollowersCount(followersCount);
      console.error('Follow error:', error);
      toast.error('Có lỗi khi thực hiện thao tác');
    }
  };

  const handleBookmark = async () => {
    const currentUser = getCurrentUser();
    if (!currentUser) {
      toast.error('Vui lòng đăng nhập để lưu bài viết');
      return;
    }

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
      navigate('/forum');
    } catch (error) {
      toast.error('Xóa bài viết thất bại');
    }
  };

  if (loading) {
    return (
      <div className="forum-post-detail-loading">
        <Loader />
      </div>
    );
  }

  if (!post) {
    return (
      <div className="forum-post-detail-error">
        Không tìm thấy bài viết
      </div>
    );
  }

  const author = post.userId && typeof post.userId === 'object' ? post.userId : null;
  const avatarUrl = author?.avatarUrl || '/unknown-avatar.jpg';
  const authorName = author?.name || author?.username || 'User';
  let postTime = 'Không xác định';
  if (post.createdAt && !isNaN(new Date(post.createdAt).getTime())) {
    postTime = formatDistanceToNow(new Date(post.createdAt), { addSuffix: true, locale: vi });
  }

  return (
    <div className="forum-post-detail">
      <div className="forum-post-detail-article">
        <div className="forum-post-detail-main">
          <div className="forum-post-detail-card">
            {/* Nút quay lại nhỏ gọn trong card */}
            <button
              className="back-button-compact"
              onClick={() => navigate(-1)}
              aria-label="Quay lại"
              style={{ position: 'absolute', top: 18, left: 18, zIndex: 2 }}
            >
              <FiArrowLeft style={{ marginRight: 4, fontSize: 18 }} />
              <span className="back-text">Quay lại</span>
            </button>
            {/* Cover Image */}
            {post.imageUrl && (
              <div className="forum-post-detail-image-wrapper">
                <img
                  src={post.imageUrl}
                  alt={post.title || 'Ảnh bài viết'}
                  title={post.title || 'Ảnh bài viết'}
                  className="forum-post-detail-image"
                />
              </div>
            )}
            {/* Header */}
            <header className="forum-post-detail-header">
              <div className="forum-post-detail-author-row">
                <Link to={`/user/${author?._id || ''}`} className="forum-post-detail-avatar-link">
                  <img
                    src={avatarUrl}
                    alt={authorName}
                    className="forum-post-detail-avatar"
                  />
                </Link>
                <div className="forum-post-detail-author-meta">
                  <span className="forum-post-detail-author-name">{authorName}</span>
                  <span className="forum-post-detail-time">{postTime}</span>
                </div>
                {author?.badge && (
                  <span className="forum-post-detail-badge">{author.badge}</span>
                )}
              </div>
              <div className="forum-post-detail-header-actions">
                {(() => {
                  const currentUser = getCurrentUser();
                  return currentUser && author && currentUser._id === author._id && !isEditing;
                })() && (
                    <>
                      <button
                        className="forum-post-detail-edit-btn"
                        onClick={() => navigate(`/forum/edit/${post._id}`)}
                        style={{ marginRight: '8px' }}
                      >
                        Chỉnh sửa
                      </button>
                      <button className="forum-post-detail-delete-btn" onClick={handleDelete}>Xóa</button>
                    </>
                  )}
              </div>
            </header>
            {/* Tiêu đề & tags */}
            <h1 className="forum-post-detail-title">{post.title}</h1>

            {/* Meta */}
            <div className="forum-post-detail-footer">
              {post.subject && (
                <span className={`forum-post-detail-category ${post.subject.toLowerCase()}`}>{getCategoryName(post.subject)}</span>
              )}
              {/* Tags */}
              {(() => {
                let tagsArray = post.tags;

                // Xử lý trường hợp tags là JSON string
                if (typeof post.tags === 'string') {
                  try {
                    tagsArray = JSON.parse(post.tags);
                  } catch (e) {
                    // Nếu không parse được, coi như là string đơn
                    tagsArray = [post.tags];
                  }
                }

                // Đảm bảo tagsArray là array
                if (!Array.isArray(tagsArray)) {
                  tagsArray = [];
                }

                return tagsArray.length > 0 ? (
                  <div className="forum-post-detail-tags-container">
                    {tagsArray.map((tag: string, index: number) => (
                      <Link
                        key={index}
                        to={`/forum?tag=${encodeURIComponent(typeof tag === 'string' ? tag : String(tag))}`}
                        className="forum-post-detail-category other clickable-tag"
                      >
                        {typeof tag === 'string' ? tag : String(tag)}
                      </Link>
                    ))}
                  </div>
                ) : null;
              })()}
              <span className="forum-post-detail-view">{viewCount} lượt xem</span>
              <span className="forum-post-detail-badge">{commentCount} bình luận</span>
              <span className="forum-post-detail-badge">{likeCount} lượt thích</span>
              <span className={`forum-post-detail-visibility-badge ${post.visibility === 'private' ? 'private' : 'public'}`}>{post.visibility === 'private' ? 'Riêng tư' : 'Công khai'}</span>
            </div>
            {/* Nội dung bài viết */}
            <section className="forum-post-detail-content">
              {isEditing ? (
                <div className="forum-post-detail-edit-form">
                  <div className="modern-form-group">
                    <label className="modern-label">Tiêu đề *</label>
                    <input
                      className="forum-post-detail-edit-title modern-input"
                      value={editTitle}
                      onChange={handleEditTitleChange}
                      required
                    />
                  </div>
                  <div className="modern-form-group">
                    <label className="modern-label">Slug</label>
                    <input
                      className="modern-input"
                      value={editSlug}
                      readOnly
                      style={{ background: '#f3f4f6', color: '#888', cursor: 'not-allowed' }}
                    />
                  </div>
                  <div className="modern-form-group">
                    <label className="modern-label">Mô tả ngắn</label>
                    <textarea
                      className="modern-input modern-textarea"
                      value={editSummary}
                      onChange={e => setEditSummary(e.target.value)}
                      rows={3}
                    />
                  </div>
                  <div className="modern-form-group">
                    <label className="modern-label">Chủ đề</label>
                    <input
                      className="modern-input"
                      value={editSubject}
                      onChange={e => setEditSubject(e.target.value)}
                    />
                  </div>
                  <div className="modern-form-group">
                    <label className="modern-label">Tags (phân cách bởi dấu phẩy)</label>
                    <input
                      className="modern-input"
                      value={editTags.join(', ')}
                      onChange={e => setEditTags(e.target.value.split(',').map(t => t.trim()).filter(Boolean))}
                    />
                  </div>
                  <div className="modern-form-group">
                    <label className="modern-label">Ảnh chủ đề</label>
                    <input
                      type="file"
                      accept="image/*"
                      onChange={e => setEditCoverImage(e.target.files && e.target.files[0] ? e.target.files[0] : null)}
                      className="modern-input"
                      aria-label="Chọn ảnh chủ đề"
                      title="Chọn ảnh chủ đề"
                    />
                    {editCoverImage ? (
                      <img src={URL.createObjectURL(editCoverImage)} alt="cover" style={{ maxWidth: 200, marginTop: 8, borderRadius: 8 }} />
                    ) : post.imageUrl && (
                      <img src={post.imageUrl} alt={post.title || 'Ảnh chủ đề'} title={post.title || 'Ảnh chủ đề'} style={{ maxWidth: 200, marginTop: 8, borderRadius: 8 }} />
                    )}
                  </div>
                  <div className="modern-form-group">
                    <label className="modern-label">Nội dung bài viết</label>
                    <RichTextEditor
                      value={editContent}
                      onChange={setEditContent}
                      placeholder="Nhập nội dung bài viết..."
                      style={{ minHeight: 200, maxHeight: 500, overflowY: 'auto', lineHeight: '1.6', position: 'relative', border: '1px solid #e5e7eb', borderRadius: 8, padding: 12, background: '#fff' }}
                    />
                  </div>
                  <div className="forum-post-detail-edit-actions">
                    <button className="forum-post-detail-edit-btn" onClick={handleSaveEdit} type="button">Lưu</button>
                    <button className="forum-post-detail-delete-btn" onClick={handleCancelEdit} type="button">Hủy</button>
                  </div>
                </div>
              ) : (
                <div
                  className="forum-post-detail-html-content"
                  style={{ whiteSpace: 'normal' }}
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

                          const imgTag = `<img src="${cleanUrl}" alt="sticker" style="max-width: 150px; max-height: 150px; border-radius: 8px; margin: 8px 0; display: block;" />`;

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
              )}
            </section>
            
            {/* Gallery ảnh & video đính kèm */}
            {post && ((post.images && post.images.length > 0) || (post.videos && post.videos.length > 0)) && (
              <div className="forum-post-detail-attachments-gallery" style={{ marginTop: '24px', padding: '20px', borderTop: '1px solid #f3f4f6', backgroundColor: '#f9fafb', borderRadius: '12px' }}>
                <h3 style={{ fontSize: '18px', fontWeight: 600, marginBottom: '16px', color: '#1f2937' }}>Tệp đính kèm</h3>
                
                {/* Section Videos */}
                {post.videos && post.videos.length > 0 && (
                  <div style={{ marginBottom: '20px' }}>
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(300px, 1fr))', gap: '16px' }}>
                      {post.videos.map((vidUrl: string, idx: number) => (
                        <div key={idx} style={{ borderRadius: '12px', overflow: 'hidden', border: '1px solid #e5e7eb', background: '#000', boxShadow: '0 4px 6px -1px rgba(0,0,0,0.1)' }}>
                          <video src={vidUrl} controls style={{ width: '100%', height: 'auto', display: 'block' }} />
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Section Images */}
                {post.images && post.images.length > 0 && (
                  <div>
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(180px, 1fr))', gap: '12px' }}>
                      {post.images.map((imgUrl: string, idx: number) => (
                        <div key={idx} style={{ borderRadius: '12px', overflow: 'hidden', border: '1px solid #e5e7eb', cursor: 'pointer', aspectRatio: '1/1', boxShadow: '0 4px 6px -1px rgba(0,0,0,0.05)', backgroundColor: '#fff' }} onClick={() => window.open(imgUrl, '_blank')}>
                          <img src={imgUrl} alt={`Attachment ${idx + 1}`} style={{ width: '100%', height: '100%', objectFit: 'cover', transition: 'transform 0.2s' }} />
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Hành động */}
            <div className="forum-post-detail-footer forum-post-detail-actions">
              <button
                onClick={handleLike}
                className={`forum-post-detail-action-btn${isLiked ? ' active like' : ''}`}
              >
                <FaHeart style={{ marginRight: 4 }} /> {likeCount}
              </button>
              <button
                onClick={handleBookmark}
                className={`forum-post-detail-action-btn${isBookmarked ? ' active bookmark' : ''}`}
              >
                <FaBookmark style={{ marginRight: 4 }} /> {saveCount}
              </button>
              <button
                onClick={handleShare}
                className="forum-post-detail-action-btn"
              >
                Chia sẻ
              </button>
              <ReportButton
                itemId={post._id}
                itemType="post"
                onReported={() => { }}
              />
            </div>
          </div>
        </div>

        {/* Sidebar */}
        <aside>
          <div className="forum-post-detail-author-card">
            {/* Header */}
            <div className="author-header">
              <div className="author-avatar-container">
                <Link to={`/profile/${author?.username || author?._id}`} className="author-avatar-link">
                  <img src={avatarUrl} alt={authorName} className="author-avatar" />
                </Link>
              </div>
              <div className="author-name-container">
                <Link to={`/profile/${author?.username || author?._id}`} className="author-name-link">
                  <h3 className="author-name">{authorName}</h3>
                </Link>
              </div>
              <div className="author-level">
                <span className="level-badge">Level {author?.level || 1}</span>
                <span className="level-title">{author?.levelTitle || 'Mới tham gia'}</span>
              </div>
              {author?.school && (
                <div className="academic-info">
                  <span className="school">{author.school}</span>
                  {author.faculty && <span className="faculty">• {author.faculty}</span>}
                  {author.major && <span className="major">• {author.major}</span>}
                </div>
              )}
              {author?.bio && <p className="author-bio">{author.bio}</p>}
            </div>

            {/* Stats Grid */}
            <div className="author-stats">
              <div className="stat-item">
                <span className="stat-number">{authorStats?.points ?? author?.points ?? 0}</span>
                <span className="stat-label">Điểm</span>
              </div>
              <div className="stat-item">
                <span className="stat-number">{authorStats?.documentsCount ?? author?.stats?.documentsCount ?? 0}</span>
                <span className="stat-label">Tài liệu</span>
              </div>
              <div className="stat-item">
                <span className="stat-number">{authorStats?.followersCount ?? followersCount}</span>
                <span className="stat-label">Theo dõi</span>
              </div>
              <div className="stat-item">
                <span className="stat-number">{authorStats?.postsCount ?? author?.stats?.postsCount ?? 0}</span>
                <span className="stat-label">Bài viết</span>
              </div>
            </div>

            {/* Recent Achievements */}
            {author?.achievements && author.achievements.length > 0 && (
              <div className="author-achievements">
                <h4>Thành tích gần đây</h4>
                <div className="achievements-list">
                  {author.achievements.slice(0, 3).map((achievement: any, index: number) => (
                    <div key={index} className="achievement-item">
                      <span className="achievement-icon">{achievement.achievementId?.icon || '🏆'}</span>
                      <span className="achievement-name">{achievement.achievementId?.name || 'Thành tích'}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Social Links */}
            {(author?.socialLinks_github || author?.socialLinks_youtube || author?.socialLinks_facebook || author?.socialLinks_tiktok) && (
              <div className="author-social">
                <div className="social-links">
                  {author.socialLinks_github && (
                    <a href={author.socialLinks_github} target="_blank" rel="noopener">
                      <i className="fab fa-github"></i>
                    </a>
                  )}
                  {author.socialLinks_youtube && (
                    <a href={author.socialLinks_youtube} target="_blank" rel="noopener">
                      <i className="fab fa-youtube"></i>
                    </a>
                  )}
                  {author.socialLinks_facebook && (
                    <a href={author.socialLinks_facebook} target="_blank" rel="noopener">
                      <i className="fab fa-facebook"></i>
                    </a>
                  )}
                </div>
              </div>
            )}

            {/* Actions - chỉ hiện khi không phải người đăng bài */}
            {(() => {
              const currentUser = getCurrentUser();
              const isOwnPost = currentUser && author && currentUser._id === author._id;

              if (isOwnPost) {
                return null; // Ẩn hoàn toàn nếu là người đăng bài
              }

              return (
                <div className="author-actions">
                  <button className="btn-follow" onClick={handleFollow}>
                    {isFollowing ? 'Đang theo dõi' : 'Theo dõi'}
                  </button>
                  <button className="btn-chat" onClick={() => openChat(author._id, { username: authorName, avatarUrl })}>
                    <FiMessageSquare />
                    Nhắn tin
                  </button>
                </div>
              );
            })()}
          </div>


          {/* Bài viết liên quan */}
          <div className="forum-post-detail-card forum-post-detail-related">
            <h3 className="related-posts-title">Bài viết liên quan</h3>
            {loadingRelated ? (
              <div className="related-posts-loading">
                <div className="loading-spinner-small"></div>
                <span>Đang tải...</span>
              </div>
            ) : relatedPosts.length > 0 ? (
              <div className="related-posts-list">
                {relatedPosts.map((relatedPost) => {
                  const postSlug = relatedPost.slug || relatedPost._id;
                  const postAuthor = relatedPost.userId?.name || relatedPost.userId?.username || 'User';
                  const postTime = relatedPost.createdAt
                    ? formatDistanceToNow(new Date(relatedPost.createdAt), { addSuffix: true, locale: vi })
                    : '';
                  // Try multiple image fields
                  const thumbnail = relatedPost.imageUrl
                    || relatedPost.coverImage
                    || relatedPost.thumbnail
                    || (relatedPost.images && relatedPost.images.length > 0 ? relatedPost.images[0] : null)
                    || '/unknown-avatar.jpg';

                  return (
                    <Link
                      to={`/forum/${postSlug}`}
                      key={relatedPost._id}
                      className="related-post-item"
                    >
                      <div className="related-post-thumbnail">
                        <img
                          src={thumbnail}
                          alt={relatedPost.title}
                          onError={(e) => {
                            const target = e.target as HTMLImageElement;
                            target.src = '/unknown-avatar.jpg';
                          }}
                        />
                      </div>
                      <div className="related-post-content">
                        <h4 className="related-post-title">{relatedPost.title}</h4>
                        <div className="related-post-meta">
                          <span className="related-post-author">{postAuthor}</span>
                          {postTime && <span className="related-post-time">• {postTime}</span>}
                        </div>
                        {relatedPost.viewCount !== undefined && (
                          <div className="related-post-stats">
                            <span><FiMessageSquare size={12} /> {relatedPost.commentCount || relatedPost.comments?.length || 0}</span>
                            <span>👁 {relatedPost.viewCount || 0}</span>
                          </div>
                        )}
                      </div>
                    </Link>
                  );
                })}
              </div>
            ) : (
              <div className="related-posts-empty">
                <p>Chưa có bài viết liên quan</p>
              </div>
            )}
          </div>
        </aside>
      </div>

      {/* Bình luận tách riêng ở dưới */}
      <section className="forum-post-detail-comments-section">
        <div className="forum-post-detail-comments-container">
          <h3 className="forum-post-detail-comments-title">Bình luận ({commentCount})</h3>
          <CommentList
            targetId={post._id}
            onCommentCountChange={handleCommentCountChange}
            authorId={post.userId._id}
            commentApi={forumApi}
          />
        </div>
      </section>

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