#!/bin/bash
# Deliberately problematic shell for ShellCheck to flag (SC2086 etc.).
name=$1
echo Hello $name
rm -rf $HOME/tmp/
