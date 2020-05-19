# sync from every 

export FILTER_NAME=MQfilter
export ROOT_CHECK=/home/jie/projects/covrare-exp-4/filter_jobs
export ROOT_WRITE=/home/jie/projects/covrare-exp-4/findings_dir


export WHO_BIN=/home/jie/projects/lava_corpus_grader/LAVA-M/who/coreutils-8.24-lava-safe/src/who
export BASE64_BIN=/home/jie/projects/lava_corpus_grader/LAVA-M/base64/coreutils-8.24-lava-safe/src/base64
export MD5_BIN=/home/jie/projects/lava_corpus_grader/LAVA-M/md5sum/coreutils-8.24-lava-safe/src/md5sum

# for who
AFL_SKIP_CPUFREQ=1 ./afl-fuzz -Q -m 1024 -t 90 -S $FILTER_NAME -s $ROOT_CHECK -o $ROOT_WRITE -- $WHO_BIN @@

# for md5
#AFL_SKIP_CPUFREQ=1 ./afl-fuzz -Q -m 1024 -t 90 -S $FILTER_NAME -s $ROOT_CHECK -o $ROOT_WRITE -- $MD5_BIN -c @@

# for base64
#AFL_SKIP_CPUFREQ=1 ./afl-fuzz -Q -m 1024 -t 90 -S $FILTER_NAME -s $ROOT_CHECK -o $ROOT_WRITE -- $BASE64_BIN -d @@