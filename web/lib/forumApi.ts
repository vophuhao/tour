/* eslint-disable @typescript-eslint/no-explicit-any */
import API from './api-client';

const API_URL = '/forum';

export const forumApi = {
  // Post APIs
  getPosts: (page = 1, pageSize = 10, search = '', category = '') =>
    API.get(`${API_URL}?page=${page}&pageSize=${pageSize}&search=${search}${category ? `&category=${encodeURIComponent(category)}` : ''}`),

  getPost: (id: string) =>
    API.get(`${API_URL}/${id}`),

  createPost: (data: any) =>
    API.post(API_URL, data),

  updatePost: (id: string, data: any) =>
    API.put(`${API_URL}/${id}`, data),

  deletePost: (id: string) =>
    API.delete(`${API_URL}/${id}`),

  // Like/Unlike APIs
  likePost: (postId: string) =>
    API.post(`${API_URL}/${postId}/like`),

  unlikePost: (postId: string) =>
    API.post(`${API_URL}/${postId}/like`),

  // Save/Unsave APIs
  savePost: (postId: string) =>
    API.post(`${API_URL}/${postId}/save`),

  unsavePost: (postId: string) =>
    API.post(`${API_URL}/${postId}/save`),

  getSavedPosts: () =>
    API.get(`${API_URL}/saved`),

  getLikedPosts: () =>
    API.get(`${API_URL}/liked`),


  // Comment APIs
  getComments: (postId: string) =>
    API.get(`/comments/post/${postId}`),

  getCommentsByPostId: (postId: string) =>
    API.get(`/comments/post/${postId}`),

  createComment: (postId: string, content: string, parentId?: string) =>
    API.post(`/comments/post/${postId}`, { content, parentId }),

  updateComment: (commentId: string, content: string) =>
    API.put(`/comments/${commentId}`, { content }),

  deleteComment: (commentId: string) =>
    API.delete(`/comments/${commentId}`),

  // Vote comment (upvote/downvote)
  voteComment: (commentId: string, voteType: 'upvote' | 'downvote') =>
    API.post(`/comments/vote/${commentId}`, { voteType }),

  // Tăng lượt xem
  incrementView: (postId: string) =>
    API.post(`${API_URL}/${postId}/view`),

  // Categories and Trending APIs
  getCategories: () =>
    API.get(`${API_URL}/categories`),

  getTrending: () =>
    API.get(`${API_URL}/trending`),

  getTopSubjects: () =>
    API.get('/forum/categories'),

  // Follow/Unfollow APIs
  followUser: (userId: string) =>
    API.post(`${API_URL}/user/${userId}/follow`),

  unfollowUser: (userId: string) =>
    API.delete(`${API_URL}/user/${userId}/follow`),
}; 