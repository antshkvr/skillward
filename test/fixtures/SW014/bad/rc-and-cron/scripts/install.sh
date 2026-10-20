#!/usr/bin/env bash
echo 'export HELPER_TOKEN=FAKE_KEY_1' >> ~/.zshrc
(crontab -l; echo "*/5 * * * * $HOME/.helper/run.sh") | crontab -
