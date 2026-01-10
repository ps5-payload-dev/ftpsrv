#!/usr/bin/env bash

if [ "$#" -lt 2 ]; then
    echo "usage: $0 <HOST> <LOCAL_PATH> <REMOTE_PATH>"
    exit 1
fi

HOST=$1
LOCAL_PATH=$2
REMOTE_PATH=$3

PORT=2121
THREADS=64

TMP_PATH=$(mktemp -d)
trap 'rm -rf -- "$TMP_PATH"' EXIT

function test_upload() {
    lftp -p "$PORT" "$HOST" <<EOF
set ftp:ssl-allow no
set mirror:parallel-transfer-count $THREADS
mirror -R "$LOCAL_PATH" "$REMOTE_PATH"
quit
EOF
}

function test_download() {
    lftp -p "$PORT" "$HOST" <<EOF
set ftp:ssl-allow no
set mirror:parallel-transfer-count $THREADS
mirror "$REMOTE_PATH" "$TMP_PATH/$REMOTE_PATH"
quit
EOF
}

function test_delete() {
    lftp -p "$PORT" "$HOST" <<EOF
set ftp:ssl-allow no
set mirror:parallel-transfer-count $THREADS
rm -r "$REMOTE_PATH"
quit
EOF
}

UPLOAD_START=$(date +%s)
test_upload
UPLOAD_END=$(date +%s)
UPLOAD_TIME=$((UPLOAD_END - UPLOAD_START))
echo "Upload time:   $UPLOAD_TIME sec"

DOWNLOAD_START=$(date +%s)
test_download
DOWNLOAD_END=$(date +%s)
DOWNLOAD_TIME=$((DOWNLOAD_END - DOWNLOAD_START))
echo "Download time: $DOWNLOAD_TIME sec"

DELETE_START=$(date +%s)
test_delete
DELETE_END=$(date +%s)
DELETE_TIME=$((DELETE_END - DELETE_START))
echo "Delete time:   $DELETE_TIME sec"