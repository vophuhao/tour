/* eslint-disable @typescript-eslint/no-explicit-any */
import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import './style/CreatePostPage.css';
import { forumApi } from '../../lib/forumApi';
import { toast } from 'react-toastify';
import {
  Upload,
  Eye,
  // EyeOff,
  Sparkles,
  // Send,
  FileText,
  Type,
  Save,
  ArrowLeft
} from 'lucide-react';
import RichTextEditor from './ui/RichTextEditor';
import PreviewModal from './ui/PreviewModal';
import '../../styles/components/modals/Dialog.css';

const SUBJECTS = [
  'Kinh nghiệm cắm trại',
  'Đồ dùng dã ngoại',
  'Địa điểm đẹp',
  'Ẩm thực ngoài trời',
  'Chia sẻ hành trình',
  'Hỏi đáp & Hỗ trợ',
  'Khác',
];

const EditPostPage = () => {
  const { postId } = useParams<{ postId: string }>();
  const navigate = useNavigate();
  
  const [title, setTitle] = useState('');
  const [slug, setSlug] = useState('');
  const [summary, setSummary] = useState('');
  const [coverImage, setCoverImage] = useState<File | null>(null);
  const [currentCoverUrl, setCurrentCoverUrl] = useState('');
  const [images, setImages] = useState<File[]>([]);
  const [videos, setVideos] = useState<File[]>([]);
  const [currentImages, setCurrentImages] = useState<string[]>([]);
  const [currentVideos, setCurrentVideos] = useState<string[]>([]);
  const [selectedTopics, setSelectedTopics] = useState<string[]>([]);
  // const [customTopic] = useState('');
  const [content, setContent] = useState('');
  const [preview, setPreview] = useState(false);
  const [loading, setLoading] = useState(false);
  const [loadingPost, setLoadingPost] = useState(true);
  // const contentRef = useRef<HTMLDivElement>(null);
  const [tags, setTags] = useState<string[]>([]);
  const [customSubject, setCustomSubject] = useState('');
  const [tagInput, setTagInput] = useState('');

  const handleImagesChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files) {
      const selectedFiles = Array.from(e.target.files);
      setImages(prev => [...prev, ...selectedFiles]);
    }
  };

  const handleVideosChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files) {
      const selectedFiles = Array.from(e.target.files);
      setVideos(prev => [...prev, ...selectedFiles]);
    }
  };

  const removeImageAttachment = (index: number) => {
    setImages(prev => prev.filter((_, i) => i !== index));
  };

  const removeVideoAttachment = (index: number) => {
    setVideos(prev => prev.filter((_, i) => i !== index));
  };

  const removeCurrentUploadedImage = (urlToRemove: string) => {
    setCurrentImages(prev => prev.filter(url => url !== urlToRemove));
  };

  const removeCurrentUploadedVideo = (urlToRemove: string) => {
    setCurrentVideos(prev => prev.filter(url => url !== urlToRemove));
  };

  // Load bài viết hiện tại
  useEffect(() => {
    const loadPost = async () => {
      if (!postId) return;
      
      try {
        setLoadingPost(true);
        const response = await forumApi.getPost(postId);
        if (response?.data) {
          const post = response.data;
          
          setTitle(post.title || '');
          setSlug(post.slug || '');
          setSummary(post.summary || '');
          setContent(post.content || '');
          setCurrentCoverUrl(post.coverImage || post.imageUrl || '');
          setCurrentImages(post.images || []);
          setCurrentVideos(post.videos || []);
          
          // Xử lý subject
          if (post.subject) {
            if (SUBJECTS.includes(post.subject)) {
              setSelectedTopics([post.subject]);
            } else {
              setSelectedTopics(['Khác']);
              setCustomSubject(post.subject);
            }
          }
          
          // Xử lý tags
          if (post.tags && Array.isArray(post.tags)) {
            const tagNames = post.tags.map((tag: any) => tag.name || tag);
            setTags(tagNames);
          }
        }
      } catch (err: any) {
        toast.error('Không thể tải bài viết: ' + (err?.response?.data?.error || 'Lỗi không xác định'));
        navigate('/forum');
      } finally {
        setLoadingPost(false);
      }
    };
    
    loadPost();
  }, [postId, navigate]);

  // Không tự sinh slug ở FE; chỉ cập nhật title, backend sẽ auto-handle
  const handleTitleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const value = e.target.value;
    setTitle(value);
  };

  const handleCoverImageChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files && e.target.files[0];
    if (file) {
      setCoverImage(file);
      setCurrentCoverUrl(''); // Xóa URL cũ khi upload ảnh mới
    }
  };

  // const allTopics = [
  //   ...selectedTopics.filter(t => t !== 'Khác'),
  //   ...(selectedTopics.includes('Khác') && customTopic.trim() ? customTopic.split(',').map(t => t.trim()).filter(Boolean) : [])
  // ];

  // Xử lý tags
  const handleTagInputKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter' || e.key === ',') {
      e.preventDefault();
      const newTag = tagInput.trim();
      if (newTag && !tags.includes(newTag)) {
        setTags([...tags, newTag]);
        setTagInput('');
      }
    }
  };

  const handleTagInputBlur = () => {
    const newTag = tagInput.trim();
    if (newTag && !tags.includes(newTag)) {
      setTags([...tags, newTag]);
      setTagInput('');
    }
  };

  const removeTag = (tagToRemove: string) => {
    setTags(tags.filter(tag => tag !== tagToRemove));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    // Kiểm tra subject
    const subjectValue = selectedTopics[0] === 'Khác' ? customSubject : selectedTopics[0];
    if (!title.trim() || !summary.trim() || !content.trim() || !subjectValue?.trim()) {
      toast.error('Vui lòng nhập đủ tiêu đề, mô tả, nội dung và chọn chủ đề!');
      return;
    }
    
    setLoading(true);
    try {
      const formData = new FormData();
      formData.append('title', title);
      // Không gửi slug; backend sẽ tự cập nhật nếu logic cho phép
      formData.append('summary', summary);
      formData.append('content', content);
      formData.append('subject', subjectValue);
      formData.append('tags', tags.join(','));
      
      // Chỉ gửi ảnh mới nếu có upload
      if (coverImage) {
        formData.append('coverImage', coverImage);
      }
      
      images.forEach(img => formData.append('images', img));
      videos.forEach(vid => formData.append('videos', vid));
      
      // Gửi danh sách các file hiện tại được giữ lại
      currentImages.forEach(url => formData.append('images', url));
      currentVideos.forEach(url => formData.append('videos', url));
      
      await forumApi.updatePost(postId!, formData);
      toast.success('Cập nhật bài viết thành công!');
      navigate(`/forum/${slug}`);
    } catch (err: any) {
      toast.error(err?.response?.data?.error || 'Cập nhật bài viết thất bại!');
    } finally {
      setLoading(false);
    }
  };

  if (loadingPost) {
    return (
      <div className="create-post-modern-root">
        <div className="create-post-modern-header">
          <div className="create-post-modern-header-inner">
            <div className="create-post-modern-header-center">
              <h1 className="create-post-modern-title">Đang tải bài viết...</h1>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="create-post-modern-root">
      {/* Header */}
      <div className="create-post-modern-header">
        <div className="create-post-modern-header-inner">
          <div className="create-post-modern-header-center">
            <button 
              onClick={() => navigate(-1)}
              className="back-button"
              style={{
                position: 'absolute',
                left: '20px',
                top: '50%',
                transform: 'translateY(-50%)',
                background: 'none',
                border: 'none',
                color: '#fff',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                fontSize: '16px'
              }}
            >
              <ArrowLeft size={20} />
              Quay lại
            </button>
            <h1 className="create-post-modern-title">
              Chỉnh sửa bài viết
            </h1>
            <p className="create-post-modern-subtitle">
              Cập nhật nội dung và thông tin bài viết
            </p>
          </div>
        </div>
      </div>
      
      {/* Main Content */}
      <div className="create-post-modern-main">
        <div className="create-post-modern-grid">
          {/* Sidebar */}
          <div className="create-post-modern-sidebar">
            <div className="modern-sidebar-sticky">
              {/* Quick Info */}
              <div className="modern-card">
                <h3 className="modern-card-title sidebar">Thông tin nhanh</h3>
                <div className="modern-sidebar-info">
                  <div className="modern-sidebar-info-row">
                    <span className="modern-sidebar-info-label">Tiêu đề:</span>
                    <span className="modern-sidebar-info-value">{title.length}/100</span>
                  </div>
                  <div className="modern-sidebar-info-row">
                    <span className="modern-sidebar-info-label">Mô tả:</span>
                    <span className="modern-sidebar-info-value">{summary.length}/300</span>
                  </div>
                  <div className="modern-sidebar-info-row">
                    <span className="modern-sidebar-info-label">Chủ đề:</span>
                    <span className="modern-sidebar-info-value">{selectedTopics[0] || 'Chưa chọn'}</span>
                  </div>
                  <div className="modern-sidebar-info-row">
                    <span className="modern-sidebar-info-label">Tags:</span>
                    <span className="modern-sidebar-info-value">{tags.length}</span>
                  </div>
                  <div className="modern-sidebar-info-row">
                    <span className="modern-sidebar-info-label">Nội dung:</span>
                    <span className="modern-sidebar-info-value">{content.replace(/<[^>]*>/g, '').length} ký tự</span>
                  </div>
                  <div className="modern-sidebar-info-row">
                    <span className="modern-sidebar-info-label">Ảnh trong bài:</span>
                    <span className="modern-sidebar-info-value">{images.length}</span>
                  </div>
                </div>
              </div>
              
              {/* Writing Tips */}
              <div className="modern-card modern-card-tips">
                <h3 className="modern-card-title tips">💡 Mẹo chỉnh sửa</h3>
                <ul className="modern-tips-list">
                  <li>• Kiểm tra lại tiêu đề và mô tả</li>
                  <li>• Cập nhật tags phù hợp</li>
                  <li>• Chỉnh sửa nội dung cẩn thận</li>
                  <li>• Thay đổi ảnh chủ đề nếu cần</li>
                  <li>• Lưu thường xuyên để tránh mất dữ liệu</li>
                </ul>
              </div>
            </div>
          </div>
          
          {/* Form Section */}
          <div className="create-post-modern-form-col">
            <form className="create-post-modern-form" onSubmit={handleSubmit}>
              {/* Ảnh chủ đề */}
              <div className="modern-card modern-cover-card">
                <div className="modern-card-header">
                  <Upload className="modern-card-icon cover" />
                  <h2 className="modern-card-title">Ảnh chủ đề</h2>
                </div>
                <div className="modern-card-body">
                  <div className="modern-cover-upload-large">
                    <input
                      type="file"
                      accept="image/*"
                      onChange={handleCoverImageChange}
                      className="modern-cover-input"
                      id="cover-image"
                    />
                    {(coverImage || currentCoverUrl) ? (
                      <div className="modern-cover-preview-large">
                        <img
                          src={coverImage ? URL.createObjectURL(coverImage) : currentCoverUrl}
                          alt="Cover preview"
                          className="modern-cover-img-large"
                        />
                        <label htmlFor="cover-image" className="modern-cover-change-btn" title="Đổi ảnh">
                          <Upload size={16} />
                        </label>
                      </div>
                    ) : (
                      <label htmlFor="cover-image" className="modern-cover-upload-placeholder">
                        <Upload size={32} />
                        <span>Chọn ảnh chủ đề</span>
                      </label>
                    )}
                    {!coverImage && currentCoverUrl && (
                      <div style={{marginTop: 8, padding: 8, background: '#f0f4ff', borderRadius: 8, border: '1px solid #c7d2fe'}}>
                        <small style={{color: '#3730a3', fontWeight: 500}}>📷 Đang dùng ảnh chủ đề hiện tại</small>
                        <br />
                        <small style={{color: '#6366f1', fontSize: '0.8rem'}}>Upload ảnh mới để thay thế</small>
                      </div>
                    )}
                    {!coverImage && !currentCoverUrl && (
                      <small style={{marginTop: 6, color: 'var(--text-secondary)'}}>Chưa có ảnh chủ đề, vui lòng chọn ảnh</small>
                    )}
                  </div>
                </div>
              </div>

              {/* Hình ảnh & video đính kèm */}
              <div className="modern-card">
                <div className="modern-card-header">
                  <Upload className="modern-card-icon cover" />
                  <h2 className="modern-card-title">Hình ảnh & video đính kèm</h2>
                </div>
                <div className="modern-card-body">
                  <div style={{ display: 'flex', gap: '16px', flexWrap: 'wrap', marginBottom: '16px' }}>
                    <div>
                      <input
                        type="file"
                        accept="image/*"
                        multiple
                        onChange={handleImagesChange}
                        id="attachment-images"
                        style={{ display: 'none' }}
                      />
                      <label htmlFor="attachment-images" className="modern-preview-btn" style={{ cursor: 'pointer', padding: '8px 16px', display: 'inline-flex', alignItems: 'center', gap: '8px' }}>
                        <Upload size={16} /> Thêm hình ảnh mới
                      </label>
                    </div>
                    <div>
                      <input
                        type="file"
                        accept="video/*"
                        multiple
                        onChange={handleVideosChange}
                        id="attachment-videos"
                        style={{ display: 'none' }}
                      />
                      <label htmlFor="attachment-videos" className="modern-preview-btn" style={{ cursor: 'pointer', padding: '8px 16px', display: 'inline-flex', alignItems: 'center', gap: '8px' }}>
                        <Upload size={16} /> Thêm video mới
                      </label>
                    </div>
                  </div>

                  {/* Previews of existing uploaded images */}
                  {currentImages.length > 0 && (
                    <div style={{ marginBottom: '16px' }}>
                      <h4 style={{ fontSize: '14px', fontWeight: 500, marginBottom: '8px', color: '#4b5563' }}>Hình ảnh hiện tại ({currentImages.length})</h4>
                      <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
                        {currentImages.map((url, idx) => (
                          <div key={idx} style={{ position: 'relative', width: '100px', height: '100px', borderRadius: '8px', overflow: 'hidden', border: '1px solid #e5e7eb' }}>
                            <img src={url} alt="Uploaded attachment" style={{ width: '100%', height: '100%', objectFit: 'cover' }} />
                            <button
                              type="button"
                              onClick={() => removeCurrentUploadedImage(url)}
                              style={{ position: 'absolute', top: '4px', right: '4px', background: 'rgba(239, 68, 68, 0.8)', color: 'white', border: 'none', borderRadius: '50%', width: '20px', height: '20px', display: 'flex', alignItems: 'center', justifyContent: 'center', cursor: 'pointer', fontSize: '12px', fontWeight: 'bold' }}
                            >
                              ×
                            </button>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Previews of newly selected images */}
                  {images.length > 0 && (
                    <div style={{ marginBottom: '16px' }}>
                      <h4 style={{ fontSize: '14px', fontWeight: 500, marginBottom: '8px', color: '#10b981' }}>Hình ảnh mới chọn ({images.length})</h4>
                      <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
                        {images.map((file, idx) => (
                          <div key={idx} style={{ position: 'relative', width: '100px', height: '100px', borderRadius: '8px', overflow: 'hidden', border: '1px solid #e5e7eb' }}>
                            <img src={URL.createObjectURL(file)} alt="New attachment" style={{ width: '100%', height: '100%', objectFit: 'cover' }} />
                            <button
                              type="button"
                              onClick={() => removeImageAttachment(idx)}
                              style={{ position: 'absolute', top: '4px', right: '4px', background: 'rgba(0,0,0,0.5)', color: 'white', border: 'none', borderRadius: '50%', width: '20px', height: '20px', display: 'flex', alignItems: 'center', justifyContent: 'center', cursor: 'pointer', fontSize: '12px' }}
                            >
                              ×
                            </button>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Previews of existing uploaded videos */}
                  {currentVideos.length > 0 && (
                    <div style={{ marginBottom: '16px' }}>
                      <h4 style={{ fontSize: '14px', fontWeight: 500, marginBottom: '8px', color: '#4b5563' }}>Videos hiện tại ({currentVideos.length})</h4>
                      <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
                        {currentVideos.map((url, idx) => (
                          <div key={idx} style={{ position: 'relative', width: '150px', height: '100px', borderRadius: '8px', overflow: 'hidden', border: '1px solid #e5e7eb', background: '#000' }}>
                            <video src={url} style={{ width: '100%', height: '100%', objectFit: 'cover' }} muted controls />
                            <button
                              type="button"
                              onClick={() => removeCurrentUploadedVideo(url)}
                              style={{ position: 'absolute', top: '4px', right: '4px', background: 'rgba(239, 68, 68, 0.8)', color: 'white', border: 'none', borderRadius: '50%', width: '20px', height: '20px', display: 'flex', alignItems: 'center', justifyContent: 'center', cursor: 'pointer', fontSize: '12px', fontWeight: 'bold' }}
                            >
                              ×
                            </button>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Previews of newly selected videos */}
                  {videos.length > 0 && (
                    <div>
                      <h4 style={{ fontSize: '14px', fontWeight: 500, marginBottom: '8px', color: '#10b981' }}>Videos mới chọn ({videos.length})</h4>
                      <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
                        {videos.map((file, idx) => (
                          <div key={idx} style={{ position: 'relative', width: '150px', height: '100px', borderRadius: '8px', overflow: 'hidden', border: '1px solid #e5e7eb', background: '#000' }}>
                            <video src={URL.createObjectURL(file)} style={{ width: '100%', height: '100%', objectFit: 'cover' }} muted />
                            <button
                              type="button"
                              onClick={() => removeVideoAttachment(idx)}
                              style={{ position: 'absolute', top: '4px', right: '4px', background: 'rgba(0,0,0,0.5)', color: 'white', border: 'none', borderRadius: '50%', width: '20px', height: '20px', display: 'flex', alignItems: 'center', justifyContent: 'center', cursor: 'pointer', fontSize: '12px' }}
                            >
                              ×
                            </button>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </div>

              {/* Tiêu đề */}
              <div className="modern-card">
                <div className="modern-card-header">
                  <Type className="modern-card-icon" />
                  <h2 className="modern-card-title">Tiêu đề *</h2>
                </div>
                <div className="modern-card-body">
                  <input
                    type="text"
                    value={title}
                    onChange={handleTitleChange}
                    placeholder="Nhập tiêu đề bài viết..."
                    className="modern-input"
                    maxLength={100}
                  />
                </div>
              </div>

              {/* Mô tả */}
              <div className="modern-card">
                <div className="modern-card-header">
                  <FileText className="modern-card-icon" />
                  <h2 className="modern-card-title">Mô tả *</h2>
                </div>
                <div className="modern-card-body">
                  <textarea
                    value={summary}
                    onChange={(e) => setSummary(e.target.value)}
                    placeholder="Mô tả ngắn gọn về bài viết..."
                    className="modern-textarea"
                    maxLength={300}
                    rows={3}
                  />
                </div>
              </div>

              {/* Chủ đề */}
              <div className="modern-card">
                <div className="modern-card-header">
                  <Sparkles className="modern-card-icon" />
                  <h2 className="modern-card-title">Chủ đề *</h2>
                </div>
                <div className="modern-card-body">
                  <div className="modern-subject-grid">
                    {SUBJECTS.map((subject) => (
                      <button
                        key={subject}
                        type="button"
                        className={`modern-subject-btn ${selectedTopics.includes(subject) ? 'selected' : ''}`}
                        onClick={() => {
                          if (subject === 'Khác') {
                            setSelectedTopics(['Khác']);
                            setCustomSubject('');
                          } else {
                            setSelectedTopics([subject]);
                            setCustomSubject('');
                          }
                        }}
                      >
                        {subject}
                      </button>
                    ))}
                  </div>
                  
                  {selectedTopics.includes('Khác') && (
                    <div className="modern-custom-subject">
                      <input
                        type="text"
                        value={customSubject}
                        onChange={(e) => setCustomSubject(e.target.value)}
                        placeholder="Nhập chủ đề tùy chỉnh..."
                        className="modern-input"
                      />
                    </div>
                  )}
                </div>
              </div>

              {/* Tags */}
              <div className="modern-card">
                <div className="modern-card-header">
                  <Sparkles className="modern-card-icon" />
                  <h2 className="modern-card-title">Tags</h2>
                </div>
                <div className="modern-card-body">
                  <div className="modern-tags-container">
                    {tags.map((tag, index) => (
                      <span key={index} className="modern-tag">
                        {tag}
                        <button
                          type="button"
                          onClick={() => removeTag(tag)}
                          className="modern-tag-remove"
                        >
                          ×
                        </button>
                      </span>
                    ))}
                  </div>
                  
                  <input
                    type="text"
                    value={tagInput}
                    onChange={(e) => setTagInput(e.target.value)}
                    onKeyDown={handleTagInputKeyDown}
                    onBlur={handleTagInputBlur}
                    placeholder="Nhập tag và nhấn Enter hoặc dấu phẩy để thêm"
                    className="modern-input"
                  />
                </div>
              </div>

              {/* Nội dung */}
              <div className="modern-card">
                <div className="modern-card-header">
                  <FileText className="modern-card-icon" />
                  <h2 className="modern-card-title">Nội dung *</h2>
                </div>
                <div className="modern-card-body">
                  <RichTextEditor
                    value={content}
                    onChange={setContent}
                    placeholder="Viết nội dung bài viết..."
                  />
                </div>
              </div>

              {/* Xem trước dùng modal chung */}
              <div className="modern-action-btns">
                <button type="button" className="modern-preview-btn" onClick={() => setPreview(true)}>
                  <Eye className="modern-preview-icon" /> Xem trước
                </button>
              </div>

              <PreviewModal
                open={preview}
                onClose={() => setPreview(false)}
                title={title}
                summary={summary}
                coverUrl={coverImage ? URL.createObjectURL(coverImage) : (currentCoverUrl || undefined)}
                topics={(selectedTopics[0] ? [selectedTopics[0] === 'Khác' ? (customSubject || 'Chủ đề') : selectedTopics[0]] : [])}
                tags={tags}
                contentHtml={content}
              />

              {/* Submit Button */}
              <div className="modern-submit-section">
                <button
                  type="submit"
                  disabled={loading}
                  className="modern-submit-btn"
                >
                  {loading ? (
                    <>
                      <div className="modern-spinner"></div>
                      Đang cập nhật...
                    </>
                  ) : (
                    <>
                      <Save size={20} />
                      Cập nhật bài viết
                    </>
                  )}
                </button>
              </div>
            </form>
          </div>
        </div>
      </div>
    </div>
  );
};

export default EditPostPage;