test: shard
	crystal spec
shard:
	shards build
clean:
	rm -rf lib && rm -f shard.lock