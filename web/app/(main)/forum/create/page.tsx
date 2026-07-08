/* eslint-disable @typescript-eslint/no-explicit-any */
"use client";

import React, { useState } from 'react';
import '../../../../components/forum/style/CreatePostPage.css';
import { forumApi } from '../../../../lib/forumApi';

import {
  generatePostContent, generatePostSummary,
  getImageSuggestions, generateImage,
  UnsplashImage
} from '../../../../lib/ai';

import { toast } from 'sonner';
import {
  Upload,
  Eye,
  Sparkles,
  Send,
  FileText,
  Type,
  Image as ImageIcon,
  Loader2,
  X,
  Download,
  Film,
  ArrowLeft
} from 'lucide-react';
import RichTextEditor from '../../../../components//forum/ui/RichTextEditor';
import PreviewModal from '../../../../components/forum/ui/PreviewModal';
import '../../../../components/forum/style/Dialog.css';
import { useRouter } from 'next/navigation';

const SUBJECTS = [
  'Kinh nghiệm cắm trại',
  'Đồ dùng dã ngoại',
  'Địa điểm đẹp',
  'Ẩm thực ngoài trời',
  'Chia sẻ hành trình',
  'Hỏi đáp & Hỗ trợ',
  'Khác',
];

const CreatePostPage = () => {
  const router = useRouter();
  const [title, setTitle] = useState('');
  const [slug, setSlug] = useState('');
  const [summary, setSummary] = useState('');
  const [coverImage, setCoverImage] = useState<File | null>(null);
  const [images, setImages] = useState<File[]>([]);
  const [videos, setVideos] = useState<File[]>([]);

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
  const [selectedTopics, setSelectedTopics] = useState<string[]>([]);
  const [customTopic, setCustomTopic] = useState('');
  const [content, setContent] = useState('');
  const [preview, setPreview] = useState(false);
  const [loading, setLoading] = useState(false);
  // const contentRef = useRef<HTMLDivElement>(null);
  const [tags, setTags] = useState<string[]>([]);
  const [customSubject, setCustomSubject] = useState('');
  const [tagInput, setTagInput] = useState('');

  // AI states
  const [aiGeneratingContent, setAiGeneratingContent] = useState(false);
  const [aiGeneratingSummary, setAiGeneratingSummary] = useState(false);
  const [aiLoadingImages, setAiLoadingImages] = useState(false);
  const [showImageModal, setShowImageModal] = useState(false);
  const [suggestedImages, setSuggestedImages] = useState<UnsplashImage[]>([]);
  const [isAIGenerated, setIsAIGenerated] = useState(false); // Track if content was AI-generated



  // Sinh slug ở FE chỉ để preview (không gửi lên BE)
  const handleTitleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const value = e.target.value;
    setTitle(value);
    const previewSlug = value
      .replace(/đ/g, 'd')
      .replace(/Đ/g, 'd')
      .normalize('NFD')
      .replace(/[\u0300-\u036f]/g, '')
      .toLowerCase()
      .replace(/[^a-z0-9\s-]/g, '')
      .replace(/\s+/g, '-')
      .replace(/-+/g, '-')
      .replace(/^-+|-+$/g, '');
    setSlug(previewSlug);
  };

  const handleCoverImageChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files && e.target.files[0];
    if (file) {
      setCoverImage(file);
    }
  };

  const allTopics = [
    ...selectedTopics.filter(t => t !== 'Khác'),
    ...(selectedTopics.includes('Khác') && customTopic.trim() ? customTopic.split(',').map(t => t.trim()).filter(Boolean) : [])
  ];

  // AI Handlers
  const handleAIGenerateContent = async () => {
    if (!title.trim()) {
      toast.warning('Vui lòng nhập tiêu đề trước khi sử dụng AI');
      return;
    }

    const subjectValue = selectedTopics[0] === 'Khác' ? customSubject : selectedTopics[0];
    if (!subjectValue?.trim()) {
      toast.warning('Vui lòng chọn chủ đề trước khi sử dụng AI');
      return;
    }

    setAiGeneratingContent(true);
    try {
      const result = await generatePostContent({
        title: title.trim(),
        subject: subjectValue,
        summary: summary.trim() || undefined
      });

      if (result.success && result.content) {
        setContent(result.content);
        setIsAIGenerated(true); // Đánh dấu bài viết được tạo bằng AI
        toast.success('Đã tạo nội dung bằng AI! Bạn có thể chỉnh sửa trước khi đăng.');
      } else {
        toast.error(result.error || 'Không thể tạo nội dung. Vui lòng thử lại.');
      }
    } catch (error: any) {
      console.error('AI generation error:', error);
      toast.error('Lỗi khi tạo nội dung. Vui lòng thử lại.');
    } finally {
      setAiGeneratingContent(false);
    }
  };

  const handleAIGenerateSummary = async () => {
    if (!title.trim()) {
      toast.warning('Vui lòng nhập tiêu đề trước khi sử dụng AI');
      return;
    }

    const subjectValue = selectedTopics[0] === 'Khác' ? customSubject : selectedTopics[0];
    if (!subjectValue?.trim()) {
      toast.warning('Vui lòng chọn chủ đề trước khi sử dụng AI');
      return;
    }

    setAiGeneratingSummary(true);
    try {
      const result = await generatePostSummary({
        title: title.trim(),
        subject: subjectValue
      });

      if (result.success && result.summary) {
        setSummary(result.summary);
        toast.success('Đã tạo mô tả bằng AI!');
      } else {
        toast.error(result.error || 'Không thể tạo mô tả. Vui lòng thử lại.');
      }
    } catch (error: any) {
      console.error('AI generation error:', error);
      toast.error('Lỗi khi tạo mô tả. Vui lòng thử lại.');
    } finally {
      setAiGeneratingSummary(false);
    }
  };

  const handleAIGetImageSuggestions = async () => {
    if (!title.trim()) {
      toast.warning('Vui lòng nhập tiêu đề trước khi tìm ảnh');
      return;
    }

    const subjectValue = selectedTopics[0] === 'Khác' ? customSubject : selectedTopics[0];
    if (!subjectValue?.trim()) {
      toast.warning('Vui lòng chọn chủ đề trước khi tìm ảnh');
      return;
    }

    setAiLoadingImages(true);
    try {
      // Thử tìm ảnh từ Unsplash trước
      const result = await getImageSuggestions(title.trim(), subjectValue);

      if (result.success && result.images && result.images.length > 0) {
        setSuggestedImages(result.images);
        setShowImageModal(true);
      } else {
        // Nếu Unsplash không tìm thấy, thử tạo ảnh bằng DALL-E
        toast.info('Không tìm thấy ảnh từ Unsplash. Đang thử tạo ảnh bằng AI...');

        try {
          const dalleResult = await generateImage({
            title: title.trim(),
            subject: subjectValue,
            size: '1792x1024',
            quality: 'hd'
          });

          if (dalleResult.success && dalleResult.imageUrl) {
            // Tạo fake image object tương thích với Unsplash format
            const aiGeneratedImage: UnsplashImage = {
              id: 'dalle-generated',
              url: dalleResult.imageUrl,
              thumb: dalleResult.imageUrl,
              full: dalleResult.imageUrl,
              download: dalleResult.imageUrl,
              description: `Ảnh được tạo bằng AI cho: ${title}`,
              author: {
                name: 'DALL-E 3',
                username: 'dalle',
                profile: 'https://openai.com/dall-e-3'
              },
              unsplashUrl: dalleResult.imageUrl,
              width: 1792,
              height: 1024
            };

            setSuggestedImages([aiGeneratedImage]);
            setShowImageModal(true);
            toast.success('✨ Đã tạo ảnh bằng AI (DALL-E 3)!');
          } else {
            // Nếu DALL-E cũng fail, hiển thị thông báo rõ ràng
            const errorMsg = dalleResult.error || 'Không thể tạo ảnh';
            if (errorMsg.includes('API key') || errorMsg.includes('not configured')) {
              toast.warning('DALL-E chưa được cấu hình. Vui lòng upload ảnh thủ công hoặc thử lại với Unsplash.');
            } else {
              toast.error(`${errorMsg}. Vui lòng upload ảnh thủ công.`);
            }
          }
        } catch (dalleError: any) {
          console.error('DALL-E generation error:', dalleError);
          if (dalleError.response?.status === 404) {
            toast.warning('Tính năng tạo ảnh bằng AI chưa sẵn sàng. Vui lòng upload ảnh thủ công.');
          } else {
            toast.error('Lỗi khi tạo ảnh bằng AI. Vui lòng upload ảnh thủ công.');
          }
        }
      }
    } catch (error: any) {
      console.error('AI image search error:', error);
      toast.error('Lỗi khi tìm/tạo ảnh. Vui lòng thử lại.');
    } finally {
      setAiLoadingImages(false);
    }
  };

  const handleSelectImage = async (image: UnsplashImage) => {
    try {
      // Download image và convert to File
      const response = await fetch(image.url);
      const blob = await response.blob();
      const file = new File([blob], `unsplash-${image.id}.jpg`, { type: 'image/jpeg' });

      setCoverImage(file);
      setShowImageModal(false);
      if (image.id === 'dalle-generated') {
        toast.success('Đã chọn ảnh được tạo bằng AI (DALL-E 3)!');
      } else {
        toast.success(`Đã chọn ảnh từ Unsplash! Photo by ${image.author.name} on Unsplash`);
      }
    } catch (error) {
      console.error('Error downloading image:', error);
      toast.error('Lỗi khi tải ảnh. Vui lòng thử lại.');
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    // Kiểm tra subject
    const subjectValue = selectedTopics[0] === 'Khác' ? customSubject : selectedTopics[0];
    if (!title.trim() || !content.trim() || !coverImage || !subjectValue?.trim()) {
      toast.error('Vui lòng nhập đủ tiêu đề, nội dung, chọn ảnh chủ đề và chọn chủ đề!');
      return;
    }
    setLoading(true);
    try {
      const formData = new FormData();
      formData.append('title', title);
      // Không gửi slug, backend sẽ tự tạo
      formData.append('summary', summary);
      formData.append('content', content);
      formData.append('subject', subjectValue);
      // Gửi tags dưới dạng string phân cách bởi dấu phẩy thay vì JSON
      formData.append('tags', tags.join(','));
      formData.append('coverImage', coverImage);
      images.forEach(img => formData.append('images', img));
      videos.forEach(vid => formData.append('videos', vid));
      // Đánh dấu bài viết được tạo bằng AI
      if (isAIGenerated) {
        formData.append('aiGenerated', 'true');
      }



      await forumApi.createPost(formData);
      toast.success('Đăng bài viết thành công!');
      // Reset all fields including AI flag
      setTitle(''); setSlug(''); setSummary(''); setCoverImage(null); setImages([]); setVideos([]); setContent(''); setSelectedTopics([]); setCustomTopic(''); setTags([]); setCustomSubject(''); setTagInput(''); setIsAIGenerated(false);
    } catch (err: any) {
      toast.error(err?.response?.data?.error || 'Đăng bài viết thất bại!');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="create-post-modern-root">
      {/* Header */}
      <div className="create-post-modern-header">
        <div className="create-post-modern-header-inner">
          <button 
            type="button"
            onClick={() => router.back()}
            className="back-button"
            style={{
              position: 'absolute',
              left: '2rem',
              top: '50%',
              transform: 'translateY(-50%)',
              background: 'none',
              border: 'none',
              color: 'var(--primary)',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              fontSize: '1.05rem',
              fontWeight: 600
            }}
          >
            <ArrowLeft size={20} />
            Quay lại diễn đàn
          </button>
          <div className="create-post-modern-header-center">
            <h1 className="create-post-modern-title">
              Đăng bài viết mới
            </h1>
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
                    <span className="modern-sidebar-info-value">{allTopics.length}</span>
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
                <h3 className="modern-card-title tips">💡 Mẹo viết bài</h3>
                <ul className="modern-tips-list">
                  <li>• Tiêu đề rõ ràng, thu hút</li>
                  <li>• Mô tả ngắn gọn, súc tích</li>
                  <li>• Nội dung có cấu trúc</li>
                  <li>• Sử dụng thanh công cụ để format</li>
                  <li>• Kéo thả ảnh trực tiếp vào bài</li>
                  <li>• Upload ảnh từ máy tính</li>
                  <li>• Dùng heading để cấu trúc</li>
                  <li>• Chọn ảnh chủ đề phù hợp</li>
                </ul>
              </div>
              {/* Preview Panel đã được di chuyển xuống dưới */}
            </div>
          </div>
          {/* Form Section */}
          <div className="create-post-modern-form-col">
            <form className="create-post-modern-form" onSubmit={handleSubmit}>
              {/* Ảnh chủ đề - tách riêng */}
              <div className="modern-card modern-cover-card">
                <div className="modern-card-header">
                  <Upload className="modern-card-icon cover" />
                  <h2 className="modern-card-title">Ảnh chủ đề *</h2>
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
                    {coverImage ? (
                      <div className="modern-cover-preview-large">
                        <img
                          src={URL.createObjectURL(coverImage)}
                          alt="Cover preview"
                          className="modern-cover-img-large"
                        />
                        <label htmlFor="cover-image" className="modern-cover-change-btn" title="Đổi ảnh">
                          <svg width="22" height="22" viewBox="0 0 20 20" fill="none"><path d="M13.586 3.586a2 2 0 0 1 2.828 2.828l-7.5 7.5a2 2 0 0 1-.878.513l-3 1a1 1 0 0 1-1.263-1.263l1-3a2 2 0 0 1 .513-.878l7.5-7.5ZM12 5l3 3M5 19h10a2 2 0 0 0 2-2v-7a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v7a2 2 0 0 0 2 2Z" stroke="#6366f1" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" /></svg>
                        </label>
                      </div>
                    ) : (
                      <label htmlFor="cover-image" className="modern-cover-label large">
                        <Upload className="modern-cover-upload-icon large" />
                        <span className="modern-cover-upload-text large">
                          Tải lên ảnh chủ đề
                        </span>
                      </label>
                    )}
                    {/* {!coverImage && (
                      <div style={{marginTop: 8, display: 'flex', flexDirection: 'column', gap: '8px'}}>
                        <small style={{color: 'var(--text-secondary)'}}>Chưa chọn ảnh, bạn có thể tải ảnh ngay bây giờ</small>
                        <button
                          type="button"
                          onClick={handleAIGetImageSuggestions}
                          disabled={aiLoadingImages || !title.trim()}
                          className="modern-ai-image-btn"
                          style={{
                            padding: '8px 16px',
                            fontSize: '14px',
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            gap: '8px',
                            background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
                            color: 'white',
                            border: 'none',
                            borderRadius: '8px',
                            cursor: aiLoadingImages || !title.trim() ? 'not-allowed' : 'pointer',
                            opacity: aiLoadingImages || !title.trim() ? 0.6 : 1,
                            fontWeight: 500,
                            transition: 'all 0.2s'
                          }}
                        >
                          {aiLoadingImages ? (
                            <>
                              <Loader2 size={16} className="spinning" />
                              Đang tìm ảnh...
                            </>
                          ) : (
                            <>
                              <ImageIcon size={16} />
                              AI tìm ảnh phù hợp
                            </>
                          )}
                        </button>
                      </div>
                    )} */}
                  </div>
                </div>
              </div>

              {/* Hình ảnh & video đính kèm */}
              <div className="modern-card">
                <div className="modern-card-header">
                  <ImageIcon className="modern-card-icon image" />
                  <h2 className="modern-card-title">Hình ảnh & video đính kèm</h2>
                </div>
                <div className="modern-card-body">
                  <div className="modern-attachments-grid">
                    <input
                      type="file"
                      accept="image/*"
                      multiple
                      onChange={handleImagesChange}
                      id="attachment-images"
                      className="modern-cover-input"
                    />
                    <label htmlFor="attachment-images" className="modern-attachment-dropzone">
                      <ImageIcon className="modern-attachment-icon" size={32} />
                      <span className="modern-attachment-title">Đính kèm hình ảnh</span>
                      <span className="modern-attachment-desc">Click hoặc kéo thả nhiều ảnh tại đây</span>
                    </label>

                    <input
                      type="file"
                      accept="video/*"
                      multiple
                      onChange={handleVideosChange}
                      id="attachment-videos"
                      className="modern-cover-input"
                    />
                    <label htmlFor="attachment-videos" className="modern-attachment-dropzone">
                      <Film className="modern-attachment-icon" size={32} />
                      <span className="modern-attachment-title">Đính kèm video</span>
                      <span className="modern-attachment-desc">Click hoặc kéo thả video tại đây</span>
                    </label>
                  </div>

                  {/* Previews */}
                  {images.length > 0 && (
                    <div className="modern-previews-section">
                      <h4 className="modern-previews-title">
                        <ImageIcon size={16} /> Hình ảnh đã chọn ({images.length})
                      </h4>
                      <div className="modern-previews-grid">
                        {images.map((file, idx) => (
                          <div key={idx} className="modern-preview-item">
                            <img src={URL.createObjectURL(file)} alt="Attachment image" className="modern-preview-media" />
                            <button
                              type="button"
                              onClick={() => removeImageAttachment(idx)}
                              className="modern-preview-delete"
                              title="Xóa ảnh"
                            >
                              <X size={14} />
                            </button>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {videos.length > 0 && (
                    <div className="modern-previews-section">
                      <h4 className="modern-previews-title">
                        <Film size={16} /> Videos đã chọn ({videos.length})
                      </h4>
                      <div className="modern-previews-grid">
                        {videos.map((file, idx) => (
                          <div key={idx} className="modern-preview-item video">
                            <video src={URL.createObjectURL(file)} className="modern-preview-media" muted />
                            <button
                              type="button"
                              onClick={() => removeVideoAttachment(idx)}
                              className="modern-preview-delete"
                              title="Xóa video"
                            >
                              <X size={14} />
                            </button>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </div>
              {/* Thông tin cơ bản + Chủ đề + Tags (đồng bộ UI với Edit) */}
              <div className="modern-card">
                <div className="modern-card-header">
                  <Type className="modern-card-icon type" />
                  <h2 className="modern-card-title">Thông tin cơ bản</h2>
                </div>
                <div className="modern-card-body">
                  <div className="modern-form-group">
                    <label className="modern-label">Tiêu đề *</label>
                    <input
                      type="text"
                      value={title}
                      onChange={handleTitleChange}
                      placeholder="Nhập tiêu đề bài viết"
                      required
                      className="modern-input"
                    />
                  </div>
                  {/* Slug preview (backend vẫn là nguồn sự thật) */}
                  <div className="modern-form-group">
                    <label className="modern-label">Slug (xem trước)</label>
                    <input
                      type="text"
                      value={slug}
                      readOnly
                      className="modern-input"
                      style={{ background: '#f3f4f6', color: '#888', cursor: 'not-allowed' }}
                    />
                  </div>
                  <div className="modern-form-group">
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                      <label className="modern-label">Mô tả ngắn</label>
                      <button
                        type="button"
                        onClick={handleAIGenerateSummary}
                        disabled={aiGeneratingSummary || !title.trim()}
                        className="modern-ai-small-btn"
                        style={{
                          padding: '4px 12px',
                          fontSize: '12px',
                          display: 'flex',
                          alignItems: 'center',
                          gap: '4px',
                          background: 'var(--primary-color)',
                          color: 'white',
                          border: 'none',
                          borderRadius: '6px',
                          cursor: aiGeneratingSummary || !title.trim() ? 'not-allowed' : 'pointer',
                          opacity: aiGeneratingSummary || !title.trim() ? 0.6 : 1
                        }}
                      >
                        {aiGeneratingSummary ? (
                          <>
                            <Loader2 size={12} className="spinning" />
                            Đang tạo...
                          </>
                        ) : (
                          <>
                            <Sparkles size={12} />
                            AI tạo mô tả
                          </>
                        )}
                      </button>
                    </div>
                    <textarea
                      value={summary}
                      onChange={e => setSummary(e.target.value)}
                      placeholder="Mô tả ngắn về bài viết (tùy chọn)"
                      rows={3}
                      className="modern-textarea modern-input"
                    />
                  </div>
                  <div className="modern-card-header" style={{ marginTop: 4 }}>
                    <Sparkles className="modern-card-icon" />
                    <h3 className="modern-card-title">Chủ đề *</h3>
                  </div>
                  <div className="modern-card-body" style={{ paddingTop: 0 }}>
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
                  <div className="modern-card-header" style={{ marginTop: 8 }}>
                    <Sparkles className="modern-card-icon" />
                    <h3 className="modern-card-title">Tags</h3>
                  </div>
                  <div className="modern-card-body" style={{ paddingTop: 0 }}>
                    <div className="modern-tags-container">
                      {tags.map((tag, index) => (
                        <span key={index} className="modern-tag">
                          {tag}
                          <button
                            type="button"
                            onClick={() => setTags(tags.filter(t => t !== tag))}
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
                      onKeyDown={(e) => {
                        if (e.key === 'Enter' || e.key === ',') {
                          e.preventDefault();
                          const newTag = tagInput.trim();
                          if (newTag && !tags.includes(newTag)) {
                            setTags([...tags, newTag]);
                            setTagInput('');
                          }
                        }
                      }}
                      onBlur={() => {
                        const newTag = tagInput.trim();
                        if (newTag && !tags.includes(newTag)) {
                          setTags([...tags, newTag]);
                          setTagInput('');
                        }
                      }}
                      placeholder="Nhập tag và nhấn Enter hoặc dấu phẩy để thêm"
                      className="modern-input"
                    />
                  </div>
                </div>
              </div>
              {/* Content Section */}
              <div className="modern-card">
                <div className="modern-card-header">
                  <FileText className="modern-card-icon file" />
                  <h2 className="modern-card-title">Nội dung bài viết</h2>
                </div>
                {/* Rich Text Editor */}
                <RichTextEditor
                  value={content}
                  onChange={setContent}
                  placeholder="Nhập nội dung bài viết..."
                  style={{ minHeight: 200, maxHeight: 500, overflowY: 'auto', lineHeight: '1.6', position: 'relative' }}
                />
                <div className="modern-editor-tip">
                  💡 Mẹo: Bạn có thể kéo thả ảnh trực tiếp vào vùng soạn thảo, upload ảnh từ máy tính, hoặc sử dụng thanh công cụ để format text
                </div>
              </div>
              {/* Action Buttons */}
              <div className="modern-action-btns">
                <button
                  type="button"
                  className="modern-ai-btn"
                  onClick={handleAIGenerateContent}
                  disabled={aiGeneratingContent || !title.trim()}
                  style={{
                    opacity: aiGeneratingContent || !title.trim() ? 0.6 : 1,
                    cursor: aiGeneratingContent || !title.trim() ? 'not-allowed' : 'pointer'
                  }}
                >
                  {aiGeneratingContent ? (
                    <>
                      <Loader2 size={18} className="modern-ai-icon spinning" />
                      Đang tạo...
                    </>
                  ) : (
                    <>
                      <Sparkles className="modern-ai-icon" />
                      AI tạo nội dung
                    </>
                  )}
                </button>
                <button type="button" onClick={() => setPreview(true)} className="modern-preview-btn">
                  <Eye className="modern-preview-icon" /> Xem trước
                </button>
                <button
                  type="submit"
                  disabled={loading}
                  className={`modern-submit-btn${loading ? ' loading' : ''}`}
                >
                  <Send className="modern-submit-icon" />
                  {loading ? 'Đang đăng...' : 'Đăng bài viết'}
                </button>
              </div>
            </form>
            <PreviewModal
              open={preview}
              onClose={() => setPreview(false)}
              title={title}
              summary={summary}
              coverUrl={coverImage ? URL.createObjectURL(coverImage) : undefined}
              topics={allTopics}
              tags={tags}
              contentHtml={content}
            />

            {/* Image Selection Modal */}
            {showImageModal && (
              <div
                className="modal-overlay"
                onClick={() => setShowImageModal(false)}
                style={{
                  position: 'fixed',
                  top: 0,
                  left: 0,
                  right: 0,
                  bottom: 0,
                  background: 'rgba(0, 0, 0, 0.5)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  zIndex: 1000,
                  padding: '20px'
                }}
              >
                <div
                  className="modal-content"
                  onClick={(e) => e.stopPropagation()}
                  style={{
                    background: 'white',
                    borderRadius: '12px',
                    padding: '24px',
                    maxWidth: '900px',
                    width: '100%',
                    maxHeight: '90vh',
                    overflow: 'auto',
                    boxShadow: '0 20px 60px rgba(0, 0, 0, 0.3)'
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
                    <h2 style={{ margin: 0, fontSize: '20px', fontWeight: 600 }}>
                      {suggestedImages.length > 0 && suggestedImages[0].id === 'dalle-generated'
                        ? '✨ Ảnh được tạo bằng AI'
                        : 'Chọn ảnh từ Unsplash'}
                    </h2>
                    <button
                      onClick={() => setShowImageModal(false)}
                      style={{
                        background: 'none',
                        border: 'none',
                        cursor: 'pointer',
                        padding: '4px',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center'
                      }}
                    >
                      <X size={24} />
                    </button>
                  </div>

                  {suggestedImages.length > 0 ? (
                    <div style={{
                      display: 'grid',
                      gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))',
                      gap: '16px'
                    }}>
                      {suggestedImages.map((image) => (
                        <div
                          key={image.id}
                          onClick={() => handleSelectImage(image)}
                          style={{
                            position: 'relative',
                            cursor: 'pointer',
                            borderRadius: '8px',
                            overflow: 'hidden',
                            border: '2px solid transparent',
                            transition: 'all 0.2s'
                          }}
                          onMouseEnter={(e) => {
                            e.currentTarget.style.borderColor = 'var(--primary-color)';
                            e.currentTarget.style.transform = 'scale(1.02)';
                          }}
                          onMouseLeave={(e) => {
                            e.currentTarget.style.borderColor = 'transparent';
                            e.currentTarget.style.transform = 'scale(1)';
                          }}
                        >
                          <img
                            src={image.thumb}
                            alt={image.description || 'Unsplash image'}
                            style={{
                              width: '100%',
                              height: '150px',
                              objectFit: 'cover',
                              display: 'block'
                            }}
                          />
                          <div style={{
                            position: 'absolute',
                            bottom: 0,
                            left: 0,
                            right: 0,
                            background: 'linear-gradient(to top, rgba(0,0,0,0.8), transparent)',
                            padding: '8px',
                            color: 'white',
                            fontSize: '11px'
                          }}>
                            {image.id === 'dalle-generated' ? (
                              <div style={{ fontWeight: 500 }}>
                                ✨ AI Generated (DALL-E 3)
                              </div>
                            ) : (
                              <>
                                <div style={{ fontWeight: 500, marginBottom: '2px' }}>
                                  Photo by {image.author.name}
                                </div>
                                {image.unsplashUrl && (
                                  <a
                                    href={image.unsplashUrl}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    onClick={(e) => e.stopPropagation()}
                                    style={{
                                      color: '#93c5fd',
                                      textDecoration: 'none',
                                      fontSize: '10px'
                                    }}
                                  >
                                    on Unsplash
                                  </a>
                                )}
                              </>
                            )}
                          </div>
                          <div style={{
                            position: 'absolute',
                            top: '8px',
                            right: '8px',
                            background: 'rgba(255, 255, 255, 0.9)',
                            borderRadius: '6px',
                            padding: '4px 8px',
                            fontSize: '11px',
                            fontWeight: 500,
                            display: 'flex',
                            alignItems: 'center',
                            gap: '4px'
                          }}>
                            <Download size={12} />
                            Chọn
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div style={{ textAlign: 'center', padding: '40px', color: 'var(--text-secondary)' }}>
                      <ImageIcon size={48} style={{ marginBottom: '16px', opacity: 0.5 }} />
                      <p>Không tìm thấy ảnh phù hợp</p>
                    </div>
                  )}

                  <div style={{ marginTop: '20px', padding: '12px', background: '#f3f4f6', borderRadius: '8px', fontSize: '12px', color: '#6b7280' }}>
                    <strong>Lưu ý:</strong> Ảnh từ Unsplash được cung cấp miễn phí theo giấy phép Unsplash License.
                    Khi sử dụng, vui lòng ghi công tác giả và link về Unsplash nếu có thể.
                    <br />
                    <a
                      href="https://unsplash.com/license"
                      target="_blank"
                      rel="noopener noreferrer"
                      style={{ color: '#6366f1', textDecoration: 'underline' }}
                    >
                      Xem thêm về Unsplash License
                    </a>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default CreatePostPage; 