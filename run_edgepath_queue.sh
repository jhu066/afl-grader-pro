export FILTER_NAME=MQfilter
export ROOT_CHECK=/home/jie/projects/eval-kirenenko/hybrid-fuzz/Kirenenko-PP-sche-res/filter_jobs
export ROOT_WRITE=/home/jie/projects/eval-kirenenko/hybrid-fuzz/Kirenenko-PP-sche-res/findings_dir

export WHO_BIN=/home/jie/projects/lava_corpus_grader/LAVA-M/who/coreutils-8.24-lava-safe/src/who

# for who
AFL_SKIP_CPUFREQ=1 ./afl-fuzz -Q -m 1024 -t 90 -S $FILTER_NAME -s $ROOT_CHECK -o $ROOT_WRITE -- $WHO_BIN @@
