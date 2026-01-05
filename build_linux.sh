#!/bin/bash
echo "🚀 开始交叉编译服务器程序 (使用 Podman)..."

# 使用更可靠的 Nightly 镜像标签来支持 Edition 2024
podman run --rm -it \
    --platform linux/amd64 \
    -v "$(pwd)":/usr/src/app:Z \
    -w /usr/src/app \
    rustlang/rust:nightly-alpine \
    sh -c "apk add --no-cache musl-dev gcc make pkgconfig openssl-dev openssl-libs-static && \
           export CARGO_TARGET_DIR=/usr/src/app/target-linux && \
           cargo build --release --bin server --target x86_64-unknown-linux-musl"

if [ $? -eq 0 ]; then
    echo "✅ 编译成功！"
    cp target-linux/x86_64-unknown-linux-musl/release/server ./server-linux-x64
    echo "📦 二进制文件已生成: ./server-linux-x64 (Static Binary)"
    echo ""
    echo "该文件不需要服务器安装任何 glibc，直接上传运行即可："
    echo "scp ./server-linux-x64 user@cloud-server-0:~/"
else
    echo "❌ 编译失败，请检查 Podman 是否正在运行且网络连接正常。"
fi
