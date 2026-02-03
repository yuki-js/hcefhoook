FROM ghcr.io/yuki-js/dotfiles/dotimage:latest AS download
USER root
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates \
        wget \
        unzip \
        xz-utils \
        git \
        && rm -rf /var/lib/apt/lists/*

ARG CMDLINE_TOOLS_REV=13114758
ARG ANDROID_STUDIO_VERSION=2023.2.1.25
RUN mkdir -p /opt/android-sdk \
    && cd /opt/android-sdk \
    && wget -qO cmdline-tools.zip "https://dl.google.com/android/repository/commandlinetools-linux-${CMDLINE_TOOLS_REV}_latest.zip" \
    && unzip -q cmdline-tools.zip -d /opt/android-sdk/cmdline-tools-tmp \
    && mkdir -p /opt/android-sdk/cmdline-tools/latest \
    && mv /opt/android-sdk/cmdline-tools-tmp/cmdline-tools/* /opt/android-sdk/cmdline-tools/latest/ \
    && rm -rf /opt/android-sdk/cmdline-tools-tmp cmdline-tools.zip

RUN ANDROID_STUDIO_URL="https://redirector.gvt1.com/edgedl/android/studio/ide-zips/${ANDROID_STUDIO_VERSION}/android-studio-${ANDROID_STUDIO_VERSION}-linux.tar.gz" \
    && wget -qO /tmp/android-studio.tar.gz "${ANDROID_STUDIO_URL}" \
    && if [ ! -s /tmp/android-studio.tar.gz ]; then echo "Android Studio download failed: ${ANDROID_STUDIO_URL}. Check network access or version." >&2; exit 1; fi \
    && tar -xzf /tmp/android-studio.tar.gz -C /opt \
    && rm /tmp/android-studio.tar.gz

FROM ghcr.io/yuki-js/dotfiles/dotimage:latest
USER root
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        git \
        libasound2 \
        libatk-bridge2.0-0 \
        libatk1.0-0 \
        libcups2 \
        libdbus-1-3 \
        libdrm2 \
        libgbm1 \
        libgtk-3-0 \
        libnss3 \
        libx11-xcb1 \
        libxcomposite1 \
        libxdamage1 \
        libxfixes3 \
        libxkbcommon0 \
        libxrandr2 \
        libxshmfence1 \
        libxtst6 \
        openjdk-17-jdk \
        xdg-utils \
        && rm -rf /var/lib/apt/lists/*

ENV ANDROID_SDK_ROOT=/opt/android-sdk
ENV ANDROID_HOME=/opt/android-sdk
ENV JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
ENV ANDROID_STUDIO_HOME=/opt/android-studio
ENV PATH="/opt/android-sdk/cmdline-tools/latest/bin:/opt/android-sdk/platform-tools:/opt/android-sdk/build-tools/34.0.0:$PATH"
ENV ANDROID_NDK_ROOT=/opt/android-sdk/ndk/25.1.8937393
ENV ANDROID_NDK_HOME=/opt/android-sdk/ndk/25.1.8937393
ENV CMAKE_HOME=/opt/android-sdk/cmake/3.22.1

COPY --from=download --chown=user:user /opt/android-sdk/cmdline-tools/latest /opt/android-sdk/cmdline-tools/latest
COPY --from=download --chown=user:user /opt/android-studio /opt/android-studio

RUN set -eux; \
    yes | sdkmanager --licenses > /dev/null || true; \
    sdkmanager "platform-tools" "platforms;android-34" "build-tools;34.0.0" "cmake;3.22.1" "ndk;25.1.8937393"

RUN ln -s /opt/android-studio/bin/studio.sh /usr/local/bin/android-studio \
    && mkdir -p /home/user/.android \
    && chown -R user:user /home/user/.android /opt/android-sdk /opt/android-studio

USER user

CMD ["/bin/zsh"]
