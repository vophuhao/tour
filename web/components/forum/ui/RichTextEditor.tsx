import React, { useRef, useEffect } from 'react';
import {
  Bold, Italic, Underline, Strikethrough, Type, List, ListOrdered, Quote, Image as ImageIcon, Link as LinkIcon, Code, Undo2, Redo2, AlignLeft, AlignCenter, AlignRight, AlignJustify, Highlighter, PaintBucket, Upload, Video
} from 'lucide-react';

interface RichTextEditorProps {
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  style?: React.CSSProperties;
}

const FONT_SIZES = [
  { label: 'Nhỏ', value: '2' },
  { label: 'Vừa', value: '3' },
  { label: 'Lớn', value: '5' },
  { label: 'Rất lớn', value: '7' },
];

const FONT_FAMILIES = [
  { label: 'Mặc định', value: '' },
  { label: 'Arial', value: 'Arial, Helvetica, sans-serif' },
  { label: 'Times New Roman', value: 'Times New Roman, Times, serif' },
  { label: 'Roboto', value: 'Roboto, Arial, sans-serif' },
  { label: 'Georgia', value: 'Georgia, serif' },
  { label: 'Courier New', value: 'Courier New, Courier, monospace' },
  { label: 'Tahoma', value: 'Tahoma, Geneva, sans-serif' },
  { label: 'Verdana', value: 'Verdana, Geneva, sans-serif' },
];

const RichTextEditor: React.FC<RichTextEditorProps> = ({ value, onChange, placeholder, style }) => {
  const editorRef = useRef<HTMLDivElement>(null);
  const colorRef = useRef<HTMLInputElement>(null);
  const highlightRef = useRef<HTMLInputElement>(null);
  const fontRef = useRef<HTMLSelectElement>(null);
  const imageUploadRef = useRef<HTMLInputElement>(null);
  const videoUploadRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (editorRef.current && editorRef.current.innerHTML !== value) {
      editorRef.current.innerHTML = value;
    }
  }, [value]);

  // Toolbar actions
  const execCommand = (command: string, value: string | null = null) => {
    document.execCommand(command, false, value ?? undefined);
    if (editorRef.current) editorRef.current.focus();
  };

  const insertHeading = (level: number) => {
    execCommand('formatBlock', `H${level}`);
  };

  const handleFontSize = (e: React.ChangeEvent<HTMLSelectElement>) => {
    execCommand('fontSize', e.target.value);
  };

  const handleFontFamily = (e: React.ChangeEvent<HTMLSelectElement>) => {
    const font = e.target.value.split(',')[0];
    execCommand('fontName', font);
  };

  const handleColor = (color: string) => {
    execCommand('foreColor', color);
  };

  const handleHighlight = (color: string) => {
    execCommand('hiliteColor', color);
  };

  const handleInsertImage = () => {
    const url = prompt('Nhập URL ảnh:');
    if (url) {
      const imgElement = document.createElement('img');
      imgElement.src = url;
      imgElement.style.maxWidth = '100%';
      imgElement.style.height = 'auto';
      imgElement.style.maxHeight = '400px';
      imgElement.style.objectFit = 'contain';
      
      const selection = window.getSelection();
      if (selection && selection.rangeCount > 0) {
        const range = selection.getRangeAt(0);
        range.deleteContents();
        range.insertNode(imgElement);
        range.collapse(false);
      }
      
      if (editorRef.current) {
        onChange(editorRef.current.innerHTML);
      }
    }
  };

  const handleInsertVideo = () => {
    const url = prompt('Nhập URL video:');
    if (url) {
      const videoElement = document.createElement('video');
      videoElement.src = url;
      videoElement.controls = true;
      videoElement.style.maxWidth = '100%';
      videoElement.style.height = 'auto';
      videoElement.style.maxHeight = '400px';
      videoElement.style.display = 'block';
      videoElement.style.margin = '8px 0';
      
      const selection = window.getSelection();
      if (selection && selection.rangeCount > 0) {
        const range = selection.getRangeAt(0);
        range.deleteContents();
        range.insertNode(videoElement);
        range.collapse(false);
      }
      
      if (editorRef.current) {
        onChange(editorRef.current.innerHTML);
      }
    }
  };

  const handleUploadImage = () => {
    imageUploadRef.current?.click();
  };

  const handleUploadVideo = () => {
    videoUploadRef.current?.click();
  };

  const handleImageFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (files) {
      Array.from(files).forEach(file => {
        if (file.type.startsWith('image/')) {
          insertImageFromFile(file);
        }
      });
    }
    e.target.value = '';
  };

  const handleVideoFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file && file.type.startsWith('video/')) {
      insertVideoFromFile(file);
    }
    e.target.value = '';
  };

  const insertImageFromFile = (file: File) => {
    const reader = new FileReader();
    reader.onload = (event) => {
      const imageUrl = event.target?.result as string;
      if (imageUrl) {
        const imgElement = document.createElement('img');
        imgElement.src = imageUrl;
        imgElement.style.maxWidth = '100%';
        imgElement.style.height = 'auto';
        imgElement.style.maxHeight = '400px';
        imgElement.style.objectFit = 'contain';
        
        const selection = window.getSelection();
        if (selection && selection.rangeCount > 0) {
          const range = selection.getRangeAt(0);
          range.deleteContents();
          range.insertNode(imgElement);
          range.collapse(false);
        }
        
        if (editorRef.current) {
          onChange(editorRef.current.innerHTML);
        }
      }
    };
    reader.readAsDataURL(file);
  };

  const insertVideoFromFile = (file: File) => {
    const reader = new FileReader();
    reader.onload = (event) => {
      const videoUrl = event.target?.result as string;
      if (videoUrl) {
        const videoElement = document.createElement('video');
        videoElement.src = videoUrl;
        videoElement.controls = true;
        videoElement.style.maxWidth = '100%';
        videoElement.style.height = 'auto';
        videoElement.style.maxHeight = '400px';
        videoElement.style.display = 'block';
        videoElement.style.margin = '8px 0';
        
        const selection = window.getSelection();
        if (selection && selection.rangeCount > 0) {
          const range = selection.getRangeAt(0);
          range.deleteContents();
          range.insertNode(videoElement);
          range.collapse(false);
        }
        
        if (editorRef.current) {
          onChange(editorRef.current.innerHTML);
        }
      }
    };
    reader.readAsDataURL(file);
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    
    const files = Array.from(e.dataTransfer.files);
    files.forEach(file => {
      if (file.type.startsWith('image/')) {
        insertImageFromFile(file);
      } else if (file.type.startsWith('video/')) {
        insertVideoFromFile(file);
      }
    });
  };

  const handleInsertLink = () => {
    const url = prompt('Nhập URL liên kết:');
    if (url) execCommand('createLink', url);
  };

  return (
    <div style={{ position: 'relative' }}>
      {/* Toolbar */}
      <div className="modern-editor-toolbar rich-toolbar-word" style={{ flexWrap: 'wrap', gap: 8, zIndex: 2 }}>
        {/* Undo/Redo */}
        <button type="button" title="Hoàn tác" onClick={() => execCommand('undo')}><Undo2 size={18} /></button>
        <button type="button" title="Làm lại" onClick={() => execCommand('redo')}><Redo2 size={18} /></button>
        <span className="rich-toolbar-divider" />
        {/* Font family */}
        <select title="Font chữ" onChange={handleFontFamily} ref={fontRef} className="rich-toolbar-font-family">
          {FONT_FAMILIES.map(f => <option key={f.label} value={f.value}>{f.label}</option>)}
        </select>
        {/* Font size */}
        <select title="Cỡ chữ" onChange={handleFontSize} defaultValue="3" className="rich-toolbar-font-size">
          {FONT_SIZES.map(f => <option key={f.value} value={f.value}>{f.label}</option>)}
        </select>
        {/* Định dạng chữ */}
        <button type="button" title="Đậm" onClick={() => execCommand('bold')}><Bold size={18} /></button>
        <button type="button" title="Nghiêng" onClick={() => execCommand('italic')}><Italic size={18} /></button>
        <button type="button" title="Gạch chân" onClick={() => execCommand('underline')}><Underline size={18} /></button>
        <button type="button" title="Gạch ngang" onClick={() => execCommand('strikeThrough')}><Strikethrough size={18} /></button>
        {/* Màu chữ */}
        <button type="button" title="Màu chữ" onClick={() => colorRef.current?.click()}><PaintBucket size={18} /></button>
        <input ref={colorRef} type="color" style={{ display: 'none' }} onChange={e => handleColor(e.target.value)} />
        {/* Highlight */}
        <button type="button" title="Highlight" onClick={() => highlightRef.current?.click()}><Highlighter size={18} /></button>
        <input ref={highlightRef} type="color" style={{ display: 'none' }} onChange={e => handleHighlight(e.target.value)} />
        
        {/* Hidden inputs */}
        <input 
          ref={imageUploadRef} 
          type="file" 
          accept="image/*" 
          multiple
          style={{ display: 'none' }} 
          onChange={handleImageFileChange} 
        />
        <input 
          ref={videoUploadRef} 
          type="file" 
          accept="video/*" 
          style={{ display: 'none' }} 
          onChange={handleVideoFileChange} 
        />
        
        {/* Heading */}
        <button type="button" title="Tiêu đề 1" onClick={() => insertHeading(1)}><Type size={18} /><span style={{fontSize:12,marginLeft:2}}>H1</span></button>
        <button type="button" title="Tiêu đề 2" onClick={() => insertHeading(2)}><Type size={18} /><span style={{fontSize:12,marginLeft:2}}>H2</span></button>
        <button type="button" title="Tiêu đề 3" onClick={() => insertHeading(3)}><Type size={18} /><span style={{fontSize:12,marginLeft:2}}>H3</span></button>
        {/* Danh sách */}
        <button type="button" title="Danh sách chấm" onClick={() => execCommand('insertUnorderedList')}><List size={18} /></button>
        <button type="button" title="Danh sách số" onClick={() => execCommand('insertOrderedList')}><ListOrdered size={18} /></button>
        {/* Căn lề */}
        <button type="button" title="Căn trái" onClick={() => execCommand('justifyLeft')}><AlignLeft size={18} /></button>
        <button type="button" title="Căn giữa" onClick={() => execCommand('justifyCenter')}><AlignCenter size={18} /></button>
        <button type="button" title="Căn phải" onClick={() => execCommand('justifyRight')}><AlignRight size={18} /></button>
        <button type="button" title="Căn đều" onClick={() => execCommand('justifyFull')}><AlignJustify size={18} /></button>
        {/* Chèn */}
        <button type="button" title="Chèn ảnh từ URL" onClick={handleInsertImage}><ImageIcon size={18} /></button>
        <button type="button" title="Upload ảnh từ máy tính" onClick={handleUploadImage}><Upload size={18} /></button>
        <button type="button" title="Chèn video từ URL" onClick={handleInsertVideo}><Video size={18} /></button>
        <button type="button" title="Upload video từ máy tính" onClick={handleUploadVideo}><Video size={18} style={{marginRight: -4}} /><Upload size={12} /></button>
        <button type="button" title="Chèn liên kết" onClick={handleInsertLink}><LinkIcon size={18} /></button>
        <button type="button" title="Trích dẫn" onClick={() => execCommand('formatBlock', 'BLOCKQUOTE')}><Quote size={18} /></button>
        <button type="button" title="Code" onClick={() => execCommand('formatBlock', 'PRE')}><Code size={18} /></button>
      </div>
      {/* Editor */}
      <div
        ref={editorRef}
        contentEditable
        className="modern-editor-content rich-editor-word"
        style={style}
        onInput={() => onChange(editorRef.current ? editorRef.current.innerHTML : '')}
        onDragOver={handleDragOver}
        onDrop={handleDrop}
        suppressContentEditableWarning
      />
      {(!value && placeholder) && (
        <div style={{
          position: 'absolute',
          pointerEvents: 'none',
          color: '#aaa',
          left: 24,
          bottom: 18,
          fontSize: '1.08rem',
          padding: '0 2px',
          zIndex: 1
        }}>{placeholder}</div>
      )}
    </div>
  );
};

export default RichTextEditor; 