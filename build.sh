#!/bin/bash

LLVM_PATH=$(brew --prefix llvm)

if [ "$1" = "release" ]; then
     AR="$LLVM_PATH/bin/llvm-ar" CC="$LLVM_PATH/bin/clang" trunk build --release
    cp ./docs/index.html ./docs/404.html
elif [ "$1" = "dev" ]; then
    AR="$LLVM_PATH/bin/llvm-ar" CC="$LLVM_PATH/bin/clang" trunk serve --public-url / --port=1334
else
    echo "Invalid argument. Please use 'release' or 'dev'."
fi
