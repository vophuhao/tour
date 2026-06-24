interface StepIndicatorProps {
  currentStep: number;
  steps: { label: string; description: string }[];
  onStepClick?: (step: number) => void;
}

export function StepIndicator({ currentStep, steps, onStepClick }: StepIndicatorProps) {
  return (
    <div className="w-full max-w-4xl mx-auto py-4">
      {/* Steps */}
      <div className="flex items-center justify-between relative px-2">
        {/* Progress line */}
        <div className="absolute top-5 left-0 right-0 h-[3px] bg-slate-100 dark:bg-slate-800 -z-10 rounded-full">
          <div
            className="h-full bg-gradient-to-r from-primary to-primary/80 transition-all duration-500 ease-out shadow-sm rounded-full"
            style={{ width: `${(currentStep / (steps.length - 1)) * 100}%` }}
          />
        </div>

        {steps.map((step, index) => {
          const isCompleted = index < currentStep;
          const isCurrent = index === currentStep;
          const isPending = index > currentStep;

          return (
            <button
              key={step.label}
              type="button"
              onClick={() => onStepClick?.(index)}
              className="flex flex-col items-center group cursor-pointer relative focus:outline-none"
              disabled={!onStepClick}
            >
              {/* Circle */}
              <div
                className={`
                  w-10 h-10 rounded-full flex items-center justify-center font-bold text-sm
                  transition-all duration-300 mb-2 relative z-10 shadow-sm
                  ${isCompleted ? "bg-gradient-to-br from-primary to-primary/80 text-white shadow-primary/20" : ""}
                  ${isCurrent ? "bg-gradient-to-br from-primary to-primary/80 text-white ring-4 ring-primary/20 dark:ring-primary/10 scale-110 shadow-md shadow-primary/30" : ""}
                  ${isPending ? "bg-white dark:bg-slate-900 border-2 border-slate-200 dark:border-slate-800 text-slate-400" : ""}
                  ${onStepClick && !isCurrent ? "group-hover:scale-105 group-hover:border-primary dark:group-hover:border-primary" : ""}
                `}
              >
                {isCompleted ? (
                  <svg className="w-5 h-5 animate-pulse" fill="none" stroke="currentColor" strokeWidth="3" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                  </svg>
                ) : (
                  <span>{index + 1}</span>
                )}
              </div>

              {/* Label */}
              <div className="text-center mt-1">
                <p
                  className={`
                    text-xs sm:text-sm font-semibold tracking-wide transition-colors duration-300
                    ${isCurrent ? "text-primary" : ""}
                    ${isCompleted ? "text-slate-700 dark:text-slate-300" : ""}
                    ${isPending ? "text-slate-400 dark:text-slate-600" : ""}
                  `}
                >
                  {step.label}
                </p>
                <p className="hidden md:block text-[10px] text-slate-400 dark:text-slate-500 font-normal mt-0.5 max-w-[120px]">
                  {step.description}
                </p>
              </div>
            </button>
          );
        })}
      </div>
    </div>
  );
}