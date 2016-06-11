# 0. make test
# 1. commit changes
# 2. bump
# 3. make release

.PHONY: test doc release

test:
	bundle exec rubocop
	bundle exec rake

doc:
	bundle exec yardoc

push: test doc
	git add doc coverage README.md
	git commit -m 'Documentation update' doc coverage README.md
	git checkout gh-pages
	git checkout master -- doc coverage
	git commit -m 'Documentation update'
	git checkout master
	git push origin gh-pages

release: test doc push
	bundle exec rake release

