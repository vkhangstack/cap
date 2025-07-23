// Performance monitoring utility for CAP.js server
// Tracks request metrics to ensure 200 QPS target is met

let requestCount = 0;
let startTime = Date.now();
let responseTimeSum = 0;
let maxResponseTime = 0;
let minResponseTime = Infinity;
let errorCount = 0;

const WINDOW_SIZE = 60000; // 1 minute window
const TARGET_QPS = 200;

const resetMetrics = () => {
  requestCount = 0;
  startTime = Date.now();
  responseTimeSum = 0;
  maxResponseTime = 0;
  minResponseTime = Infinity;
  errorCount = 0;
};

export const trackRequest = (responseTime, isError = false) => {
  requestCount++;
  responseTimeSum += responseTime;
  maxResponseTime = Math.max(maxResponseTime, responseTime);
  minResponseTime = Math.min(minResponseTime, responseTime);

  if (isError) {
    errorCount++;
  }
};

export const getMetrics = () => {
  const elapsed = Date.now() - startTime;
  const qps = requestCount / (elapsed / 1000);
  const avgResponseTime = responseTimeSum / requestCount || 0;
  const errorRate = (errorCount / requestCount) * 100 || 0;

  return {
    requestCount,
    qps: Math.round(qps * 100) / 100,
    avgResponseTime: Math.round(avgResponseTime * 100) / 100,
    maxResponseTime,
    minResponseTime: minResponseTime === Infinity ? 0 : minResponseTime,
    errorRate: Math.round(errorRate * 100) / 100,
    targetQPS: TARGET_QPS,
    meetsTarget: qps >= TARGET_QPS * 0.9, // 90% of target
    uptime: elapsed,
  };
};

export const performanceMiddleware = () => {
  return (request, response, next) => {
    const startTime = Date.now();

    const originalSend = response.send;
    response.send = function (...args) {
      const responseTime = Date.now() - startTime;
      const isError = response.statusCode >= 400;
      trackRequest(responseTime, isError);
      return originalSend.apply(this, args);
    };

    return next();
  };
};

// Auto-reset metrics every minute
setInterval(() => {
  const metrics = getMetrics();
  console.log(
    `📊 Performance: ${metrics.qps} QPS (target: ${TARGET_QPS}), avg response: ${metrics.avgResponseTime}ms, errors: ${metrics.errorRate}%`
  );

  if (metrics.qps < TARGET_QPS * 0.8) {
    console.warn(`⚠️  Performance below 80% of target (${metrics.qps}/${TARGET_QPS} QPS)`);
  }

  resetMetrics();
}, WINDOW_SIZE);

export default {
  trackRequest,
  getMetrics,
  performanceMiddleware,
  resetMetrics,
};
