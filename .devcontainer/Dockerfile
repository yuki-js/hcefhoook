FROM mcr.microsoft.com/devcontainers/base:ubuntu-22.04

ARG USERNAME=vscode
ARG USER_UID=1000
ARG USER_GID=1000

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        git \
        gnupg \
        libasound2 \
        libatk1.0-0 \
        libatk-bridge2.0-0 \
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
        mesa-utils \
        openjdk-17-jdk \
        unzip \
        wget \
        xdg-utils \
        && apt-get clean \
        && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /opt/android-sdk/cmdline-tools \
    && curl -sSLo /tmp/cmdline-tools.zip https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip \
    && unzip -q /tmp/cmdline-tools.zip -d /opt/android-sdk/cmdline-tools \
    && mv /opt/android-sdk/cmdline-tools/cmdline-tools /opt/android-sdk/cmdline-tools/latest \
    && rm /tmp/cmdline-tools.zip

ENV ANDROID_SDK_ROOT=/opt/android-sdk
ENV ANDROID_HOME=/opt/android-sdk
ENV PATH=$PATH:/opt/android-sdk/cmdline-tools/latest/bin:/opt/android-sdk/platform-tools:/opt/android-sdk/build-tools/34.0.0

RUN yes | sdkmanager --licenses \
    && sdkmanager \
        "platform-tools" \
        "platforms;android-34" \
        "build-tools;34.0.0" \
        "ndk;25.1.8937393" \
        "cmake;3.22.1"

RUN curl -sSLo /tmp/android-studio.tar.gz https://redirector.gvt1.com/edgedl/android/studio/ide-zips/2023.2.1.25/android-studio-2023.2.1.25-linux.tar.gz \
    && tar -xzf /tmp/android-studio.tar.gz -C /opt \
    && ln -s /opt/android-studio/bin/studio.sh /usr/local/bin/android-studio \
    && rm /tmp/android-studio.tar.gz

RUN groupmod --gid ${USER_GID} ${USERNAME} \
    && usermod --uid ${USER_UID} --gid ${USER_GID} ${USERNAME} \
    && mkdir -p /home/${USERNAME}/.android \
    && chown -R ${USERNAME}:${USERNAME} /home/${USERNAME} /opt/android-sdk /opt/android-studio
