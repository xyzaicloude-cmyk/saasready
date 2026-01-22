import React from 'react';
import Layout from '@theme/Layout';
import Link from '@docusaurus/Link';
import styles from './index.module.css';

function Home() {
    return (
        <Layout
            title="SaaSReady"
            description="Open source multi‑tenant authentication and RBAC backend">
            <main className={styles.main}>
                <h1 className={styles.title}>SaaSReady</h1>
                <p className={styles.tagline}>Open‑source, self‑hosted authentication &amp; RBAC for SaaS.</p>
                <Link
                    className={styles.getStarted}
                    to="/docs/">
                    Get Started →
                </Link>
            </main>
        </Layout>
    );
}

export default Home;
