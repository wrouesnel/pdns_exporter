FROM scratch

COPY pdns_exporter /pdns_exporter

EXPOSE 9120

ENTRYPOINT [ "/pdns_exporter" ]
