# sync from every 

export FILTER_NAME=MQfilter
export ROOT_CHECK=/home/jie/projects/hybrid-root/filter_jobs
export ROOT_WRITE=/home/jie/projects/hybrid-root/findings_dir


export WHO_BIN=/home/jie/projects/lava_corpus_grader/LAVA-M/who/coreutils-8.24-lava-safe/src/who
export BASE64_BIN=/home/jie/projects/lava_corpus_grader/LAVA-M/base64/coreutils-8.24-lava-safe/src/base64

# for who
# AFL_SKIP_CPUFREQ=1 ./afl-fuzz -Q -m 1024 -t 90 -S $FILTER_NAME -s $ROOT_CHECK -o $ROOT_WRITE -- $WHO_BIN @@

# for base64
AFL_SKIP_CPUFREQ=1 ./afl-fuzz -Q -m 1024 -t 90 -S $FILTER_NAME -s $ROOT_CHECK -o $ROOT_WRITE -- $BASE64_BIN -d @@