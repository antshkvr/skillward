#!/bin/bash
timeout 1 bash -c "</dev/tcp/localhost/5432" && echo up
