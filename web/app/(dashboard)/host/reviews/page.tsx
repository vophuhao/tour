/* eslint-disable @typescript-eslint/no-explicit-any */
"use client";

import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import {
    Select,
    SelectContent,
    SelectItem,
    SelectTrigger,
    SelectValue,
} from "@/components/ui/select";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import {
    Star,
    MessageSquare,
    Calendar,
    MapPin,
    Check,
    Search,
    TrendingUp,
    Award,
    ChevronRight,
} from "lucide-react";
import { useEffect, useState } from "react";
import { toast } from "sonner";
import { Input } from "@/components/ui/input";
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";
import { getMyCampsitesReview } from "@/lib/client-actions";
import { ReviewDetailDialog } from "@/components/reviews/review-detail-dialog";
import { ReviewResponseDialog } from "@/components/reviews/review-response-dialog";

export default function ReviewsPage() {
    const [reviews, setReviews] = useState<any[]>([]);
    const [filteredReviews, setFilteredReviews] = useState<any[]>([]);
    const [activeTab, setActiveTab] = useState("all");
    const [sortBy, setSortBy] = useState("newest");
    const [searchTerm, setSearchTerm] = useState("");
    const [loading, setLoading] = useState(true);
    
    // Detail dialog
    const [detailDialog, setDetailDialog] = useState<{
        open: boolean;
        review: any | null;
    }>({ open: false, review: null });
    
    // Response dialog
    const [responseDialog, setResponseDialog] = useState<{
        open: boolean;
        review: any | null;
    }>({ open: false, review: null });

    useEffect(() => {
        fetchReviews();
    }, []);

    useEffect(() => {
        filterReviews();
    }, [reviews, activeTab, sortBy, searchTerm]);

    async function fetchReviews() {
        try {
            setLoading(true);
            const res = await getMyCampsitesReview();
            setReviews(res.data || []);
        } catch (error) {
            console.error("Error fetching reviews:", error);
            toast.error("Có lỗi khi tải danh sách đánh giá");
        } finally {
            setLoading(false);
        }
    }

    function filterReviews() {
        let filtered = [...reviews];

        if (activeTab === "pending") {
            filtered = filtered.filter((r) => !r.hostResponse);
        } else if (activeTab === "responded") {
            filtered = filtered.filter((r) => r.hostResponse);
        } else if (activeTab === "featured") {
            filtered = filtered.filter((r) => r.isFeatured);
        } else if (activeTab === "high-rated") {
            filtered = filtered.filter((r) => r.overallRating >= 4);
        } else if (activeTab === "low-rated") {
            filtered = filtered.filter((r) => r.overallRating < 4);
        }

        if (searchTerm) {
            const term = searchTerm.toLowerCase();
            filtered = filtered.filter(
                (r) =>
                    r.guest?.username?.toLowerCase().includes(term) ||
                    r.property?.name?.toLowerCase().includes(term) ||
                    r.site?.name?.toLowerCase().includes(term) ||
                    r.comment?.toLowerCase().includes(term)
            );
        }

        filtered.sort((a, b) => {
            switch (sortBy) {
                case "newest":
                    return new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime();
                case "oldest":
                    return new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime();
                case "rating-high":
                    return (b.overallRating || 0) - (a.overallRating || 0);
                case "rating-low":
                    return (a.overallRating || 0) - (b.overallRating || 0);
                case "most-helpful":
                    return (b.helpfulCount || 0) - (a.helpfulCount || 0);
                default:
                    return 0;
            }
        });

        setFilteredReviews(filtered);
    }

    function openDetailDialog(review: any) {
        setDetailDialog({ open: true, review });
    }

    function openResponseDialog(review: any) {
        setResponseDialog({ open: true, review });
        setDetailDialog({ open: false, review: null });
    }

    function formatDate(date: string) {
        return new Date(date).toLocaleDateString("vi-VN", {
            day: "2-digit",
            month: "2-digit",
            year: "numeric",
        });
    }

    function getStarColor(rating: number) {
        if (rating >= 4.5) return "text-green-500";
        if (rating >= 3.5) return "text-yellow-500";
        return "text-red-500";
    }

    const stats = {
        total: reviews.length,
        pending: reviews.filter((r) => !r.hostResponse).length,
        responded: reviews.filter((r) => r.hostResponse).length,
        featured: reviews.filter((r) => r.isFeatured).length,
        avgRating: reviews.length
            ? (reviews.reduce((sum, r) => sum + (r.overallRating || 0), 0) / reviews.length).toFixed(1)
            : 0,
    };

    return (
        <div className="min-h-screen">
            {/* Header */}
            <div className="bg-white ">
                <div className="mx-auto max-w-6xl px-4 py-6 sm:px-6 lg:px-8">
                    <div className="flex items-center justify-between">
                        <div>
                            <h1 className="text-3xl font-bold text-gray-900">Quản lý đánh giá</h1>
                          
                        </div>
                    </div>
                </div>
            </div>

            {/* Stats */}
            <div className="mx-auto max-w-6xl px-4 py-6 sm:px-6 lg:px-8">
                <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-5">
                    <Card>
                        <CardContent className="p-6">
                            <div className="flex items-center">
                                <div className="flex h-12 w-12 items-center justify-center rounded-lg bg-blue-100">
                                    <Star className="h-6 w-6 text-blue-600" />
                                </div>
                                <div className="ml-4">
                                    <p className="text-sm font-medium text-gray-500">Tổng số</p>
                                    <p className="text-2xl font-bold text-gray-900">{stats.total}</p>
                                </div>
                            </div>
                        </CardContent>
                    </Card>

                    <Card>
                        <CardContent className="p-6">
                            <div className="flex items-center">
                                <div className="flex h-12 w-12 items-center justify-center rounded-lg bg-yellow-100">
                                    <MessageSquare className="h-6 w-6 text-yellow-600" />
                                </div>
                                <div className="ml-4">
                                    <p className="text-sm font-medium text-gray-500">Chờ phản hồi</p>
                                    <p className="text-2xl font-bold text-gray-900">{stats.pending}</p>
                                </div>
                            </div>
                        </CardContent>
                    </Card>

                    <Card>
                        <CardContent className="p-6">
                            <div className="flex items-center">
                                <div className="flex h-12 w-12 items-center justify-center rounded-lg bg-green-100">
                                    <Check className="h-6 w-6 text-green-600" />
                                </div>
                                <div className="ml-4">
                                    <p className="text-sm font-medium text-gray-500">Đã phản hồi</p>
                                    <p className="text-2xl font-bold text-gray-900">{stats.responded}</p>
                                </div>
                            </div>
                        </CardContent>
                    </Card>

                    <Card>
                        <CardContent className="p-6">
                            <div className="flex items-center">
                                <div className="flex h-12 w-12 items-center justify-center rounded-lg bg-purple-100">
                                    <Award className="h-6 w-6 text-purple-600" />
                                </div>
                                <div className="ml-4">
                                    <p className="text-sm font-medium text-gray-500">Nổi bật</p>
                                    <p className="text-2xl font-bold text-gray-900">{stats.featured}</p>
                                </div>
                            </div>
                        </CardContent>
                    </Card>

                    <Card>
                        <CardContent className="p-6">
                            <div className="flex items-center">
                                <div className="flex h-12 w-12 items-center justify-center rounded-lg bg-emerald-100">
                                    <TrendingUp className="h-6 w-6 text-emerald-600" />
                                </div>
                                <div className="ml-4">
                                    <p className="text-sm font-medium text-gray-500">Đánh giá TB</p>
                                    <p className="text-2xl font-bold text-gray-900">
                                        {stats.avgRating}{" "}
                                        <Star className="inline h-5 w-5 fill-yellow-400 text-yellow-400" />
                                    </p>
                                </div>
                            </div>
                        </CardContent>
                    </Card>
                </div>
            </div>

            {/* Filters */}
            <div className="mx-auto max-w-6xl px-4 sm:px-6 lg:px-8">
                <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
                    <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full sm:w-auto">
                        <TabsList className="grid w-full grid-cols-3 sm:grid-cols-6 sm:w-auto">
                            <TabsTrigger value="all">Tất cả</TabsTrigger>
                            <TabsTrigger value="pending">Chờ phản hồi</TabsTrigger>
                            <TabsTrigger value="responded">Đã phản hồi</TabsTrigger>
                            <TabsTrigger value="featured">Nổi bật</TabsTrigger>
                            <TabsTrigger value="high-rated">≥ 4 sao</TabsTrigger>
                            <TabsTrigger value="low-rated">&lt; 4 sao</TabsTrigger>
                        </TabsList>
                    </Tabs>

                    <div className="flex gap-2">
                        <div className="relative flex-1 sm:w-64">
                            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-400" />
                            <Input
                                placeholder="Tìm kiếm..."
                                value={searchTerm}
                                onChange={(e) => setSearchTerm(e.target.value)}
                                className="pl-10"
                            />
                        </div>

                        <Select value={sortBy} onValueChange={setSortBy}>
                            <SelectTrigger className="w-[180px]">
                                <SelectValue placeholder="Sắp xếp" />
                            </SelectTrigger>
                            <SelectContent>
                                <SelectItem value="newest">Mới nhất</SelectItem>
                                <SelectItem value="oldest">Cũ nhất</SelectItem>
                                <SelectItem value="rating-high">Đánh giá cao</SelectItem>
                                <SelectItem value="rating-low">Đánh giá thấp</SelectItem>
                                <SelectItem value="most-helpful">Hữu ích nhất</SelectItem>
                            </SelectContent>
                        </Select>
                    </div>
                </div>
            </div>

            {/* Reviews List */}
            <div className="mx-auto max-w-6xl px-4 py-6 sm:px-6 lg:px-8">
                {loading ? (
                    <div className="flex items-center justify-center py-12">
                        <div className="h-8 w-8 animate-spin rounded-full border-4 border-emerald-600 border-t-transparent"></div>
                    </div>
                ) : filteredReviews.length === 0 ? (
                    <Card>
                        <CardContent className="py-12 text-center">
                            <Star className="mx-auto h-12 w-12 text-gray-400" />
                            <h3 className="mt-2 text-lg font-medium text-gray-900">Chưa có đánh giá nào</h3>
                            <p className="mt-1 text-sm text-gray-500">
                                {searchTerm ? "Không tìm thấy kết quả phù hợp" : "Các đánh giá sẽ hiển thị ở đây"}
                            </p>
                        </CardContent>
                    </Card>
                ) : (
                    <div className="space-y-3">
                        {filteredReviews.map((review) => (
                            <Card
                                key={review._id}
                                className="cursor-pointer transition-all hover:shadow-md hover:border-emerald-200"
                                onClick={() => openDetailDialog(review)}
                            >
                                <CardContent className="p-4">
                                    <div className="flex items-center justify-between gap-4">
                                        {/* Left: Guest info */}
                                        <div className="flex items-center gap-3 flex-1 min-w-0">
                                            <Avatar className="h-10 w-10 flex-shrink-0">
                                                <AvatarImage src={review.guest?.avatarUrl} />
                                                <AvatarFallback>
                                                    {review.guest?.username?.charAt(0).toUpperCase() || "?"}
                                                </AvatarFallback>
                                            </Avatar>
                                            <div className="flex-1 min-w-0">
                                                <div className="flex items-center gap-2">
                                                    <h3 className="font-medium text-gray-900 truncate">
                                                        {review.guest?.username}
                                                    </h3>
                                                    {review.isVerified && (
                                                        <Badge variant="secondary" className="text-xs flex-shrink-0">
                                                            <Check className="mr-1 h-3 w-3" />
                                                            Verified
                                                        </Badge>
                                                    )}
                                                    {review.isFeatured && (
                                                        <Badge className="bg-purple-600 text-xs flex-shrink-0">
                                                            <Award className="mr-1 h-3 w-3" />
                                                            Featured
                                                        </Badge>
                                                    )}
                                                </div>
                                                <div className="flex items-center gap-2 text-sm text-gray-500 mt-1">
                                                    <MapPin className="h-3 w-3 flex-shrink-0" />
                                                    <span className="truncate">
                                                        {review.property?.name} - {review.site?.name}
                                                    </span>
                                                    <span className="flex-shrink-0">•</span>
                                                    <Calendar className="h-3 w-3 flex-shrink-0" />
                                                    <span className="flex-shrink-0">{formatDate(review.createdAt)}</span>
                                                </div>
                                            </div>
                                        </div>

                                        {/* Middle: Comment preview */}
                                        <div className="hidden md:block flex-1 min-w-0">
                                            <p className="text-sm text-gray-600 truncate">{review.comment}</p>
                                        </div>

                                        {/* Right: Rating & Status */}
                                        <div className="flex items-center gap-4 flex-shrink-0">
                                            <div className="flex items-center gap-1">
                                                <Star
                                                    className={`h-5 w-5 fill-current ${getStarColor(
                                                        review.overallRating || 0
                                                    )}`}
                                                />
                                                <span className="font-semibold text-gray-900">
                                                    {review.overallRating?.toFixed(1) || "0.0"}
                                                </span>
                                            </div>

                                            {review.hostResponse ? (
                                                <Badge variant="outline" className="bg-green-50 text-green-700 border-green-200">
                                                    <Check className="mr-1 h-3 w-3" />
                                                    Đã phản hồi
                                                </Badge>
                                            ) : (
                                                <Badge variant="outline" className="bg-yellow-50 text-yellow-700 border-yellow-200">
                                                    <MessageSquare className="mr-1 h-3 w-3" />
                                                    Chờ phản hồi
                                                </Badge>
                                            )}

                                            <ChevronRight className="h-5 w-5 text-gray-400" />
                                        </div>
                                    </div>
                                </CardContent>
                            </Card>
                        ))}
                    </div>
                )}
            </div>

            {/* Dialogs */}
            <ReviewDetailDialog
                open={detailDialog.open}
                review={detailDialog.review}
                onOpenChange={(open) => setDetailDialog({ ...detailDialog, open })}
                onResponse={openResponseDialog}
            />

            <ReviewResponseDialog
                open={responseDialog.open}
                review={responseDialog.review}
                onOpenChange={(open) => setResponseDialog({ ...responseDialog, open })}
                onSuccess={fetchReviews}
            />
        </div>
    );
}