import {
  AmenityService,
  AuthService,
  BookingService,
  BookingQueryService,
  BookingLifecycleService,
  BookingNotificationService,
  EmailTemplateService,
  CommentService,
  ForumService,
  // Hipcamp-style services
  NotificationService,
  PropertyService,
  ReviewService,
  SiteService,
  VerificationService,
} from "@/services";
import { Container } from "./container";
import { TOKENS } from "./tokens";

import DirectMessageService from "@/services/directMessage.service";

export const container = new Container();

// Register services
container.register(TOKENS.DirectMessageService, () => new DirectMessageService(), {
  singleton: true,
});
container.register(TOKENS.NotificationService, () => new NotificationService(), { singleton: true });
container.register(TOKENS.VerificationService, () => new VerificationService(), {
  singleton: true,
});

container.register(
  TOKENS.AuthService,
  () => new AuthService(container.resolve(TOKENS.VerificationService)),
  { singleton: true }
);

// Register Hipcamp-style services
container.register(TOKENS.BookingService, () => new BookingService(), { singleton: true });
container.register(TOKENS.BookingQueryService, () => new BookingQueryService(), { singleton: true });
container.register(TOKENS.BookingLifecycleService, () => new BookingLifecycleService(), { singleton: true });
container.register(TOKENS.BookingNotificationService, () => new BookingNotificationService(), { singleton: true });
container.register(TOKENS.EmailTemplateService, () => new EmailTemplateService(), { singleton: true });
container.register(TOKENS.ReviewService, () => new ReviewService(), { singleton: true });
container.register(TOKENS.AmenityService, () => new AmenityService(), { singleton: true });
container.register(TOKENS.PropertyService, () => new PropertyService(), { singleton: true });
container.register(TOKENS.SiteService, () => new SiteService(), { singleton: true });
container.register(TOKENS.CommentService, () => new CommentService(), { singleton: true });
container.register(TOKENS.ForumService, () => new ForumService(), { singleton: true });

export type { Container } from "./container";
export { TOKENS } from "./tokens";
