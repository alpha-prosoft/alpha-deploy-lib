SHELL:=/bin/bash

push: 
	git add --all &&\
		git commit --amend --no-edit &&\
		git push origin HEAD:refs/heads/master -f
