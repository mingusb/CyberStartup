PROJECT = patent_draft
LATEX = pdflatex

all: $(PROJECT).pdf

$(PROJECT).pdf: $(PROJECT).tex
	$(LATEX) $(PROJECT).tex
	$(LATEX) $(PROJECT).tex

clean:
	rm -f *.aux *.log *.out *.pdf *.toc *.lof *.lot *.fls *.fdb_latexmk *.synctex.gz
