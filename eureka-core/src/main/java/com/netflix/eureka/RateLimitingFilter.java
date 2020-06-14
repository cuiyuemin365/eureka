/*
 * Copyright 2014 Netflix, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.netflix.eureka;

import javax.inject.Inject;
import javax.inject.Singleton;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.netflix.appinfo.AbstractEurekaIdentity;
import com.netflix.appinfo.EurekaClientIdentity;
import com.netflix.eureka.util.EurekaMonitors;
import com.netflix.discovery.util.RateLimiter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Rate limiting filter, with configurable threshold above which non-privileged clients
 * will be dropped. This feature enables cutting off non-standard and potentially harmful clients
 * in case of system overload. Since it is critical to always allow client registrations and heartbeats into
 * the system, which at the same time are relatively cheap operations, the rate limiting is applied only to
 * full and delta registry fetches. Furthermore, since delta fetches are much smaller than full fetches,
 * and if not served my result in following full registry fetch from the client, they have relatively
 * higher priority. This is implemented by two parallel rate limiters, one for overall number of
 * full/delta fetches (higher threshold) and one for full fetches only (low threshold).
 * <p>
 * The client is identified by {@link AbstractEurekaIdentity#AUTH_NAME_HEADER_KEY} HTTP header
 * value. The privileged group by default contains:
 * <ul>
 * <li>
 *     {@link EurekaClientIdentity#DEFAULT_CLIENT_NAME} - standard Java eureka-client. Applications using
 *     this client automatically belong to the privileged group.
 * </li>
 * <li>
 *     {@link com.netflix.eureka.EurekaServerIdentity#DEFAULT_SERVER_NAME} - connections from peer Eureka servers
 *     (internal only, traffic replication)
 * </li>
 * </ul>
 * It is possible to turn off privileged client filtering via
 * {@link EurekaServerConfig#isRateLimiterThrottleStandardClients()} property.
 * <p>
 * Rate limiting is not enabled by default, but can be turned on via configuration. Even when disabled,
 * the throttling statistics are still counted, although on a separate counter, so it is possible to
 * measure the impact of this feature before activation.
 *
 * <p>
 * Rate limiter implementation is based on token bucket algorithm. There are two configurable
 * parameters:
 * <ul>
 * <li>
 *     burst size - maximum number of requests allowed into the system as a burst
 * </li>
 * <li>
 *     average rate - expected number of requests per second
 * </li>
 * </ul>
 *
 * @author Tomasz Bak
 */
//速率限制过滤器，具有可配置的阈值，超过该阈值，非特权客户端将被删除。该特性允许在系统过载时切断非标准的、可能有害的客户机。
// 由于始终允许客户端注册和心跳进入系统是至关重要的，这同时也是相对便宜的操作，因此速率限制仅适用于完整和增量注册表获取。
// 此外，由于delta获取要比完全获取小得多，而且如果不满足我从客户端执行完整注册表获取的结果，它们具有相对较高的优先级。
// 这是由两个并行的速率限制器实现的，一个用于全/增量提取的总数(较高的阈值)，另一个用于全提取(低阈值)。
//客户端由AbstractEurekaIdentity标识。AUTH_NAME_HEADER_KEY HTTP头值。特权组默认包含:
//EurekaClientIdentity。DEFAULT_CLIENT_NAME -标准的Java eureka-client。使用此客户机的应用程序自动属于特权组。
//EurekaServerIdentity。DEFAULT_SERVER_NAME—来自同级Eureka服务器的连接(仅限于内部，流量复制)
//可以通过EurekaServerConfig.isRateLimiterThrottleStandardClients()属性关闭特权客户端过滤。
//速率限制在默认情况下是不启用的，但是可以通过配置启用。即使禁用了，节流统计信息仍然会被计算，尽管是在一个单独的计数器上，因此可以在激活之前度量此特性的影响。
//速率限制器的实现是基于令牌桶算法。有两个可配置参数:
//突发大小——允许以突发形式进入系统的请求的最大数量
//平均速率——期望的每秒请求数
@Singleton
public class RateLimitingFilter implements Filter {

    private static final Logger logger = LoggerFactory.getLogger(RateLimitingFilter.class);

    private static final Set<String> DEFAULT_PRIVILEGED_CLIENTS = new HashSet<String>(
            Arrays.asList(EurekaClientIdentity.DEFAULT_CLIENT_NAME, EurekaServerIdentity.DEFAULT_SERVER_NAME)
    );

    private static final Pattern TARGET_RE = Pattern.compile("^.*/apps(/[^/]*)?$");

    enum Target {FullFetch, DeltaFetch, Application, Other}

    /**
     * Includes both full and delta fetches.
     */
    private static final RateLimiter registryFetchRateLimiter = new RateLimiter(TimeUnit.SECONDS);

    /**
     * Only full registry fetches.
     */
    private static final RateLimiter registryFullFetchRateLimiter = new RateLimiter(TimeUnit.SECONDS);

    private EurekaServerConfig serverConfig;

    @Inject
    public RateLimitingFilter(EurekaServerContext server) {
        this.serverConfig = server.getServerConfig();
    }

    // for non-DI use
    public RateLimitingFilter() {
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        if (serverConfig == null) {
            EurekaServerContext serverContext = (EurekaServerContext) filterConfig.getServletContext()
                    .getAttribute(EurekaServerContext.class.getName());
            serverConfig = serverContext.getServerConfig();
        }
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        Target target = getTarget(request);
        if (target == Target.Other) {
            chain.doFilter(request, response);
            return;
        }

        HttpServletRequest httpRequest = (HttpServletRequest) request;

        if (isRateLimited(httpRequest, target)) {
            incrementStats(target);
            if (serverConfig.isRateLimiterEnabled()) {
                ((HttpServletResponse) response).setStatus(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
                return;
            }
        }
        chain.doFilter(request, response);
    }

    private static Target getTarget(ServletRequest request) {
        Target target = Target.Other;
        if (request instanceof HttpServletRequest) {
            HttpServletRequest httpRequest = (HttpServletRequest) request;
            String pathInfo = httpRequest.getRequestURI();

            if ("GET".equals(httpRequest.getMethod()) && pathInfo != null) {
                Matcher matcher = TARGET_RE.matcher(pathInfo);
                if (matcher.matches()) {
                    if (matcher.groupCount() == 0 || matcher.group(1) == null || "/".equals(matcher.group(1))) {
                        target = Target.FullFetch;
                    } else if ("/delta".equals(matcher.group(1))) {
                        target = Target.DeltaFetch;
                    } else {
                        target = Target.Application;
                    }
                }
            }
            if (target == Target.Other) {
                logger.debug("URL path {} not matched by rate limiting filter", pathInfo);
            }
        }
        return target;
    }

    private boolean isRateLimited(HttpServletRequest request, Target target) {
        if (isPrivileged(request)) {
            logger.debug("Privileged {} request", target);
            return false;
        }
        if (isOverloaded(target)) {
            logger.debug("Overloaded {} request; discarding it", target);
            return true;
        }
        logger.debug("{} request admitted", target);
        return false;
    }

    private boolean isPrivileged(HttpServletRequest request) {
        if (serverConfig.isRateLimiterThrottleStandardClients()) {
            return false;
        }
        Set<String> privilegedClients = serverConfig.getRateLimiterPrivilegedClients();
        String clientName = request.getHeader(AbstractEurekaIdentity.AUTH_NAME_HEADER_KEY);
        return privilegedClients.contains(clientName) || DEFAULT_PRIVILEGED_CLIENTS.contains(clientName);
    }

    private boolean isOverloaded(Target target) {
        int maxInWindow = serverConfig.getRateLimiterBurstSize();
        int fetchWindowSize = serverConfig.getRateLimiterRegistryFetchAverageRate();
        boolean overloaded = !registryFetchRateLimiter.acquire(maxInWindow, fetchWindowSize);

        if (target == Target.FullFetch) {
            int fullFetchWindowSize = serverConfig.getRateLimiterFullFetchAverageRate();
            overloaded |= !registryFullFetchRateLimiter.acquire(maxInWindow, fullFetchWindowSize);
        }
        return overloaded;
    }

    private void incrementStats(Target target) {
        if (serverConfig.isRateLimiterEnabled()) {
            EurekaMonitors.RATE_LIMITED.increment();
            if (target == Target.FullFetch) {
                EurekaMonitors.RATE_LIMITED_FULL_FETCH.increment();
            }
        } else {
            EurekaMonitors.RATE_LIMITED_CANDIDATES.increment();
            if (target == Target.FullFetch) {
                EurekaMonitors.RATE_LIMITED_FULL_FETCH_CANDIDATES.increment();
            }
        }
    }

    @Override
    public void destroy() {
    }

    // For testing purposes
    static void reset() {
        registryFetchRateLimiter.reset();
        registryFullFetchRateLimiter.reset();
    }
}
