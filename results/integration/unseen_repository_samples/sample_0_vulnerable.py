def _download_sql_proxy_if_needed(self) -> None:
        if os.path.isfile(self.sql_proxy_path):
            self.log.info("cloud-sql-proxy is already present")
            return
        system = platform.system().lower()
        processor = os.uname().machine
        if processor == "x86_64":
            processor = "amd64"
        if not self.sql_proxy_version:
            download_url = CLOUD_SQL_PROXY_DOWNLOAD_URL.format(system, processor)
        else:
            download_url = CLOUD_SQL_PROXY_VERSION_DOWNLOAD_URL.format(
                self.sql_proxy_version, system, processor
            )
        proxy_path_tmp = self.sql_proxy_path + ".tmp"
        self.log.info("Downloading cloud_sql_proxy from %s to %s", download_url, proxy_path_tmp)
        # httpx has a breaking API change (follow_redirects vs allow_redirects)
        # and this should work with both versions (cf. issue #20088)
        if "follow_redirects" in signature(httpx.get).parameters.keys():
            response = httpx.get(download_url, follow_redirects=True)
        else:
            response = httpx.get(download_url, allow_redirects=True)  # type: ignore[call-arg]
        # Downloading to .tmp file first to avoid case where partially downloaded
        # binary is used by parallel operator which uses the same fixed binary path
        with open(proxy_path_tmp, "wb") as file:
            file.write(response.content)
        if response.status_code != 200:
            raise AirflowException(
                "The cloud-sql-proxy could not be downloaded. "
                f"Status code = {response.status_code}. Reason = {response.reason_phrase}"
            )

        self.log.info("Moving sql_proxy binary from %s to %s", proxy_path_tmp, self.sql_proxy_path)
        shutil.move(proxy_path_tmp, self.sql_proxy_path)
        os.chmod(self.sql_proxy_path, 0o744)  # Set executable bit
        self.sql_proxy_was_downloaded = True