#!/usr/bin/env bash

name=notetool
echo $name
echo $name.egg-info

if [ "$1" = "build" ]; then
  echo build
  # 编译
  python setup.py build
  # 生成 tar.gz
  python setup.py sdist
  # 生成 egg 包
  python setup.py bdist_egg
  # 生成 wheel 包
  python setup.py bdist_wheel

  #twine register dist/*
  # 发布包
  twine upload dist/*

  rm -rf $name.egg-info
  rm -rf dist
  rm -rf build
fi

if [ "push" = "push" ]; then
  echo build
  git pull
  git add -A
  git commit -a -m "add"
  git push
fi
