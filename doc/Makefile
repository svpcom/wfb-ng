all: wfb-ng-std-draft.html

%.html:  %.md
	pandoc --self-contained  -V include-before='<style>body {max-width:unset!important}</style>' --from markdown $^ -o $@
